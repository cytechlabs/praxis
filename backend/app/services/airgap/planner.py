"""Airgap bundle planner (PRA-160 slice #1).

Resolves ``profile_slugs`` + snapshot selector into a fully-populated
``BundleDescriptor`` — or refuses with a structured reason. The
planner runs **before** any DB row is created (planner-validation
refusals do NOT create an ``airgap_bundles`` row; they emit
``airgap_export_refused`` audit only).

Locks (PRA-160 design conversation):
  * Profile-scoped is the operator-facing primitive. Channels and
    mirrors are derived. Mirror-only or channel-only exports are not
    first-class in v1.
  * Snapshot selector base ∈ ``latest | pinned``. Per-mirror explicit
    overrides via ``overrides[mirror_slug]=run_id`` layer on top.
  * **Pinned/explicit run validation must prove bytes, not assume
    them.** PRA-157 ``live/`` is always last-promoted → "current
    bytes" = the latest ``status='ok'`` run. If the operator-selected
    run's manifest_sha256 disagrees with the latest-ok manifest_sha256
    for that mirror, REFUSE (PRA-157 doesn't keep historical bytes).
  * Mixed package_family across the requested profile set is illegal
    — channels and profiles already enforce single-family
    composition; the cross-profile family check rides on the same
    rule.
  * Soft-deleted profiles, channels, mirrors are dormant — the
    planner refuses if a requested profile is soft-deleted, and
    silently skips soft-deleted channels/mirrors per the
    ContentProfileService.resolve_mirror_entries_for_profile lock.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from ...db.models import (
    ContentChannel,
    ContentChannelRepo,
    ContentProfile,
    ContentProfileChannel,
    MirrorRepo,
    MirrorSigningKey,
    MirrorSyncRun,
)
from .schema import (
    BUNDLE_SCHEMA_VERSION,
    BundleDescriptor,
    ChannelDescriptor,
    ChannelRepoDescriptor,
    MirrorRunDescriptor,
    ProfileDescriptor,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Refusal types (raised before any side effect; route handler maps to 422/409)
# ---------------------------------------------------------------------------


class PlannerRefusal(Exception):
    """Base class for planner-side refusals.

    ``code`` is a stable string the route handler surfaces in the
    response body so the operator + CLI can branch on it without
    string-matching the message. ``context`` carries structured
    detail.
    """

    code: str = "planner_refused"

    def __init__(self, message: str, context: Optional[dict] = None) -> None:
        super().__init__(message)
        self.context = context or {}


class UnknownProfile(PlannerRefusal):
    code = "unknown_profile"


class MixedPackageFamily(PlannerRefusal):
    code = "mixed_package_family"


class EmptyProfile(PlannerRefusal):
    code = "empty_profile"


class UnknownOverrideMirror(PlannerRefusal):
    code = "override_mirror_not_in_scope"


class InvalidOverrideRun(PlannerRefusal):
    code = "override_run_invalid"


class HistoricalBytesUnavailable(PlannerRefusal):
    """Selected run's manifest sha256 disagrees with current live tree.

    PRA-157 ``live/`` is always last-promoted, so older runs' bytes
    are not retained. The planner refuses rather than silently
    bundling current bytes under an older run id.
    """

    code = "historical_bytes_unavailable"


class NoSnapshotAvailable(PlannerRefusal):
    """Mirror has no ``status='ok'`` run yet — nothing to export."""

    code = "no_snapshot_available"


class DeltaNotImplemented(PlannerRefusal):
    """Retired in slice #4 — kept for backwards-compatible
    refusal-code stability. v1 always validates delta scope.
    """

    code = "delta_not_implemented"


class DeltaParentMissing(PlannerRefusal):
    """``kind='delta'`` requested but ``parent_bundle_id`` resolves
    to no row in ``airgap_bundles`` on this instance.

    Delta exports are anchored to a parent bundle that THIS Praxis
    instance previously built (so it can read the parent's
    descriptor on disk). Cross-instance parents are deferred to a
    future slice.
    """

    code = "delta_parent_missing"


class DeltaParentNotOk(PlannerRefusal):
    """Parent bundle row exists but isn't ``status='ok'``.

    A delta against a parent that didn't finish building has no
    payload index on disk to diff against.
    """

    code = "delta_parent_not_ok"


class DeltaParentScopeMismatch(PlannerRefusal):
    """Delta scope contains a mirror not in the parent bundle.

    A delta is per-file diff against the parent's payload_index.
    A new mirror that didn't exist in the parent has no parent
    baseline to diff against — that's a "full re-export" workflow,
    not a delta.
    """

    code = "delta_parent_scope_mismatch"


class PinUnusable(PlannerRefusal):
    """``--snapshot pinned`` requested but a channel pin can't be honored.

    Either the pinned ``mirror_sync_runs`` row is missing or its
    status is not ``ok``. Slice #1-a tightens this from log-only
    fallback to a structured refusal: silent fallback to latest is
    too easy to miss when the operator's whole intent was "ship the
    pinned snapshot".
    """

    code = "pin_unusable"


class ConflictingPins(PlannerRefusal):
    """Multiple channels pin the same mirror to runs with different
    manifest sha256 values.

    A bundle is a single byte snapshot per mirror, so two channels
    referencing the same mirror with conflicting pins can't both be
    honored. Refuse loudly rather than silently picking one.
    """

    code = "conflicting_pins"


class MirrorSigningMaterialMissing(PlannerRefusal):
    """A mirror in scope has no usable armored public key material
    for its manifest signer.

    The bundle descriptor declares per-mirror signing keys; the
    bundle-level signature covers them, and the importer trusts only
    keys declared inside the signed descriptor. Including a mirror
    whose declared armored bytes are empty would create a signed
    descriptor whose manifest signature can't be verified offline —
    refuse rather than ship a partially-trustable bundle.
    """

    code = "mirror_signing_material_missing"


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------


@dataclass
class _MirrorPick:
    """Internal: one mirror + its selected run + the channel repo links
    that referenced it (for descriptor denormalization)."""

    mirror: MirrorRepo
    run: MirrorSyncRun
    channel_repos: list  # List[Tuple[ContentChannelRepo, ContentChannel]]
    pinned_for_any_channel: bool


class AirgapPlanner:
    """Resolve a profile-scoped export request into a BundleDescriptor."""

    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def plan(
        self,
        *,
        profile_slugs: List[str],
        snapshot_selector_base: str,
        snapshot_overrides: Optional[Dict[str, int]],
        kind: str,
        parent_bundle_id: Optional[str],
        bundle_signing_fingerprint: str,
    ) -> BundleDescriptor:
        """Resolve and return a ``BundleDescriptor`` or raise ``PlannerRefusal``.

        The descriptor's ``payload_index`` is empty — slice #2
        populates it after tar assembly and re-signs the descriptor.
        """
        parent_descriptor: Optional[BundleDescriptor] = None
        if kind == "delta":
            # Slice #4: validate the parent row + descriptor exist
            # locally. The actual per-file diff happens in
            # ``compute_delta_payload_index`` during tar assembly;
            # planner only ensures we can locate the parent and that
            # the requested scope is a subset of the parent's mirror
            # scope.
            parent_descriptor = self._validate_delta_parent(
                parent_bundle_id=parent_bundle_id,
                profile_slugs=profile_slugs,
            )

        profiles = self._load_profiles(profile_slugs)
        package_family = self._assert_single_family(profiles)
        mirror_picks = self._select_mirrors(
            profiles=profiles,
            base=snapshot_selector_base,
            overrides=snapshot_overrides or {},
        )
        if not mirror_picks:
            # For deltas, an empty current scope is a
            # post-export drift signal (every parent mirror has been
            # dropped from the requested profiles). Surface as
            # DeltaParentScopeMismatch so the operator gets the
            # parent context, not the generic EmptyProfile.
            if kind == "delta":
                raise DeltaParentScopeMismatch(
                    f"delta against parent "
                    f"{parent_descriptor.bundle_id if parent_descriptor else parent_bundle_id!r} "
                    "resolves to no current mirror entries; every parent "
                    "mirror appears to have been dropped from the "
                    "requested profiles. Re-export full, or restore the "
                    "channel/mirror configuration.",
                    {
                        "parent_bundle_id": parent_bundle_id,
                        "profile_slugs": profile_slugs,
                        "reason": "all_mirrors_dropped",
                        # Cap the slug list and include
                        # the count so fleet-sized parents don't
                        # produce noisy error bodies.
                        "parent_mirror_slugs": (
                            sorted(m.mirror_slug for m in parent_descriptor.mirrors)[
                                :25
                            ]
                            if parent_descriptor is not None
                            else []
                        ),
                        "parent_mirror_count": (
                            len(parent_descriptor.mirrors)
                            if parent_descriptor is not None
                            else 0
                        ),
                    },
                )
            # Profiles exist but compose no live mirror entries (every
            # channel soft-deleted, or every channel has no repos, or
            # every referenced mirror is soft-deleted).
            raise EmptyProfile(
                f"profiles {profile_slugs!r} resolve to no mirror entries; "
                "nothing to export",
                {"profile_slugs": profile_slugs},
            )

        if kind == "delta":
            # Validate current mirror scope against
            # the parent's mirror set AFTER _select_mirrors. The
            # earlier profile-slug check covered "the profile
            # existed in parent" but missed the case where the
            # profile was edited post-export to add a new mirror /
            # channel — that mirror has no parent baseline to diff
            # against, so the delta would be unassemble-able.
            self._validate_delta_mirror_scope(
                parent_descriptor=parent_descriptor,
                mirror_picks=mirror_picks,
            )

        descriptor = self._build_descriptor(
            profiles=profiles,
            mirror_picks=mirror_picks,
            kind=kind,
            parent_bundle_id=parent_bundle_id,
            bundle_signing_fingerprint=bundle_signing_fingerprint,
            package_family=package_family,
        )
        return descriptor

    # ------------------------------------------------------------------
    # Slice #4: delta parent validation
    # ------------------------------------------------------------------

    def _validate_delta_parent(
        self, *, parent_bundle_id: Optional[str], profile_slugs: List[str]
    ) -> BundleDescriptor:
        """Verify the parent bundle exists locally + has a usable
        on-disk descriptor. Returns the parent ``BundleDescriptor``
        so the caller can run mirror-scope validation against it
        post-_select_mirrors.

        Refuses ``DeltaParentMissing`` if the row doesn't exist,
        ``DeltaParentNotOk`` if it isn't ``status='ok'`` or its
        descriptor file is missing, and
        ``DeltaParentScopeMismatch`` if any of the requested
        profiles aren't part of the parent's profile set.
        """
        # Lazy import — db.models references this module's package.
        from ...db.models import AirgapBundle  # pylint: disable=import-outside-toplevel
        from .schema import (  # pylint: disable=import-outside-toplevel
            deserialize_descriptor,
        )

        if not parent_bundle_id:
            # Schema layer (ImportRequest) already enforces this for
            # the route, but a direct caller into the planner could
            # pass kind='delta' with no parent — guard.
            raise DeltaParentMissing(
                "kind='delta' requires parent_bundle_id",
                {"reason": "no_parent_bundle_id"},
            )
        parent_row = (
            self.db.query(AirgapBundle)
            .filter(AirgapBundle.bundle_id == parent_bundle_id)
            .one_or_none()
        )
        if parent_row is None:
            raise DeltaParentMissing(
                f"parent bundle bundle_id={parent_bundle_id!r} not found in "
                "airgap_bundles on this instance",
                {"parent_bundle_id": parent_bundle_id},
            )
        if parent_row.status != "ok":
            raise DeltaParentNotOk(
                f"parent bundle bundle_id={parent_bundle_id!r} is in "
                f"status={parent_row.status!r}; delta requires the "
                "parent to be a completed export",
                {
                    "parent_bundle_id": parent_bundle_id,
                    "parent_status": parent_row.status,
                },
            )
        if not parent_row.bundle_descriptor_path:
            raise DeltaParentNotOk(
                f"parent bundle bundle_id={parent_bundle_id!r} has no "
                "bundle_descriptor_path; cannot compute per-file diff",
                {
                    "parent_bundle_id": parent_bundle_id,
                    "reason": "missing_descriptor_path",
                },
            )
        descriptor_file = Path(parent_row.bundle_descriptor_path)
        if not descriptor_file.exists():
            raise DeltaParentNotOk(
                f"parent bundle descriptor file {descriptor_file} is "
                "missing on disk; cannot diff",
                {
                    "parent_bundle_id": parent_bundle_id,
                    "descriptor_path": str(descriptor_file),
                    "reason": "descriptor_file_missing",
                },
            )
        # Read + deserialize defensively so a corrupt descriptor
        # surfaces as a clean refusal here rather than mid-tar-build.
        try:
            parent_descriptor = deserialize_descriptor(descriptor_file.read_bytes())
        except Exception as exc:  # pylint: disable=broad-except
            raise DeltaParentNotOk(
                f"parent bundle descriptor at {descriptor_file} is "
                f"unreadable or invalid: {exc!r}",
                {
                    "parent_bundle_id": parent_bundle_id,
                    "descriptor_path": str(descriptor_file),
                    "reason": "descriptor_unreadable",
                    "error": str(exc),
                },
            ) from exc
        parent_profile_slugs = {p.slug for p in parent_descriptor.profiles}
        missing_in_parent = [s for s in profile_slugs if s not in parent_profile_slugs]
        if missing_in_parent:
            raise DeltaParentScopeMismatch(
                f"requested profiles {missing_in_parent!r} are not part of "
                f"parent bundle {parent_bundle_id!r} (parent has "
                f"{sorted(parent_profile_slugs)!r}); deltas can only "
                "narrow or match the parent's scope",
                {
                    "parent_bundle_id": parent_bundle_id,
                    "missing_in_parent": missing_in_parent,
                    "parent_profile_slugs": sorted(parent_profile_slugs),
                },
            )
        return parent_descriptor

    def _validate_delta_mirror_scope(
        self,
        *,
        parent_descriptor: Optional[BundleDescriptor],
        mirror_picks: List[_MirrorPick],
    ) -> None:
        """Refuse if the current mirror scope adds
        any mirror that wasn't in the parent.

        The earlier profile-slug check (``_validate_delta_parent``)
        catches "the profile didn't exist in the parent" but misses
        the more common drift case: a profile whose slug was already
        in the parent has had a new channel/mirror added since.
        That mirror has no parent payload to diff against, so the
        delta can't carry baseline files for it — and the post-
        assembly manifest sha would later diverge regardless. Refuse
        synchronously here with the structured mirror diff so the
        operator can either re-export full or roll back the recent
        profile/channel edits.
        """
        if parent_descriptor is None:
            # Defensive: ``plan`` only calls this when kind='delta'
            # and parent has been validated. Skip if somehow None.
            return
        parent_mirror_slugs = {m.mirror_slug for m in parent_descriptor.mirrors}
        new_mirror_slugs = sorted(
            {
                pick.mirror.slug
                for pick in mirror_picks
                if pick.mirror.slug not in parent_mirror_slugs
            }
        )
        if new_mirror_slugs:
            raise DeltaParentScopeMismatch(
                f"current scope contains mirror(s) {new_mirror_slugs!r} "
                f"that were not in parent bundle "
                f"{parent_descriptor.bundle_id!r}; deltas cannot baseline "
                "new mirrors. Re-export full, or roll back the channel/"
                "mirror addition.",
                {
                    "parent_bundle_id": parent_descriptor.bundle_id,
                    "new_mirror_slugs": new_mirror_slugs[:25],
                    "new_mirror_count": len(new_mirror_slugs),
                    # Cap parent slug list + include count
                    # so fleet-sized parents stay readable in error bodies.
                    "parent_mirror_slugs": sorted(parent_mirror_slugs)[:25],
                    "parent_mirror_count": len(parent_mirror_slugs),
                    "reason": "new_mirror_in_delta_scope",
                },
            )

    # ------------------------------------------------------------------
    # Step 1: profile resolution
    # ------------------------------------------------------------------

    def _load_profiles(self, slugs: List[str]) -> List[ContentProfile]:
        rows = (
            self.db.query(ContentProfile).filter(ContentProfile.slug.in_(slugs)).all()
        )
        by_slug = {p.slug: p for p in rows}
        missing: List[str] = []
        deleted: List[str] = []
        for slug in slugs:
            profile = by_slug.get(slug)
            if profile is None:
                missing.append(slug)
            elif profile.deleted_at is not None:
                deleted.append(slug)
        if missing or deleted:
            raise UnknownProfile(
                f"profile(s) not found or soft-deleted: missing={missing!r} "
                f"soft_deleted={deleted!r}",
                {
                    "missing": missing,
                    "soft_deleted": deleted,
                    "requested": slugs,
                },
            )
        # Preserve operator's slug ordering for deterministic descriptor
        # output.
        return [by_slug[s] for s in slugs]

    def _assert_single_family(self, profiles: List[ContentProfile]) -> str:
        families = sorted({p.package_family for p in profiles})
        if len(families) > 1:
            raise MixedPackageFamily(
                f"export profiles span multiple package families: "
                f"{families!r}; one bundle = one family",
                {
                    "families": families,
                    "profile_slugs": [p.slug for p in profiles],
                },
            )
        return families[0]

    # ------------------------------------------------------------------
    # Step 2: mirror + run selection
    # ------------------------------------------------------------------

    def _select_mirrors(
        self,
        *,
        profiles: List[ContentProfile],
        base: str,
        overrides: Dict[str, int],
    ) -> List[_MirrorPick]:
        # Lazy import — content_profile_service depends on db.models;
        # this module is imported during route registration which can
        # race with content_profile_service's own imports.
        from ..content_profile_service import (  # pylint: disable=import-outside-toplevel
            ContentProfileService,
        )

        service = ContentProfileService(self.db)

        # Walk every profile's resolved mirror entries; merge into a
        # mirror_id-keyed map so the same mirror referenced by
        # multiple profiles/channels lands as one descriptor entry.
        # Track ALL pins per mirror: if two channels
        # pin one mirror to different manifest sha256s, that's a hard
        # conflict — a bundle is one byte snapshot per mirror.
        mirror_ids_seen: Dict[int, MirrorRepo] = {}
        pin_run_ids_per_mirror: Dict[int, List[int]] = {}
        for profile in profiles:
            entries = service.resolve_mirror_entries_for_profile(profile.id)
            for entry in entries:
                if entry.mirror_id not in mirror_ids_seen:
                    mirror = (
                        self.db.query(MirrorRepo)
                        .filter(MirrorRepo.id == entry.mirror_id)
                        .one_or_none()
                    )
                    if mirror is None or mirror.deleted_at is not None:
                        continue
                    mirror_ids_seen[entry.mirror_id] = mirror
                if entry.pinned_run_id is not None:
                    pin_run_ids_per_mirror.setdefault(entry.mirror_id, []).append(
                        entry.pinned_run_id
                    )

        # Conflict detection. Per mirror with
        # any pin, validate EVERY unique pin row first — every channel
        # pin must reference an ``ok`` run, regardless of whether one
        # or many channels pin this mirror. Only after all pins are
        # ok do we compute the manifest-sha conflict logic. This
        # closes the gap where an equal-sha pin set could have one
        # non-ok pin silently dropped during the conflict pick.
        pinned_run_per_mirror: Dict[int, int] = {}
        for mirror_id, run_ids in pin_run_ids_per_mirror.items():
            unique_run_ids = sorted(set(run_ids))
            if not unique_run_ids:
                # Defensive: ``pin_run_ids_per_mirror`` only gets
                # entries when ``entry.pinned_run_id is not None``,
                # so an empty list shouldn't reach here. Cheap
                # short-circuit so a future caller
                # populating with empty lists doesn't drop into
                # ``WHERE id IN ()`` territory.
                continue
            mirror = mirror_ids_seen[mirror_id]
            run_rows = (
                self.db.query(MirrorSyncRun)
                .filter(MirrorSyncRun.id.in_(unique_run_ids))
                .all()
            )
            rows_by_id = {r.id: r for r in run_rows}
            for rid in unique_run_ids:
                row = rows_by_id.get(rid)
                if row is None:
                    # Defensive: FK is ON DELETE SET NULL, so a
                    # vanished pin row should never appear in
                    # ``pinned_run_id``. Kept as insurance against
                    # schema-behavior drift.
                    raise PinUnusable(
                        f"channel pin run_id={rid} for mirror "
                        f"'{mirror.slug}' references a missing run row",
                        {
                            "mirror_slug": mirror.slug,
                            "pinned_run_id": rid,
                            "reason": "pin_run_missing",
                        },
                    )
                # The planner is the final airgap
                # trust gate. Even though the API service normally
                # prevents cross-mirror pins, a stale or manual DB
                # row could point a channel repo for mirror A at an
                # ok run from mirror B. With matching shas, conflict
                # detection wouldn't catch it. Refuse loudly here.
                if row.mirror_repo_id != mirror.id:
                    raise PinUnusable(
                        f"channel pin run_id={rid} for mirror "
                        f"'{mirror.slug}' belongs to a different mirror "
                        f"(mirror_repo_id={row.mirror_repo_id}); pins "
                        "must reference runs of the mirror they pin",
                        {
                            "mirror_slug": mirror.slug,
                            "pinned_run_id": rid,
                            "pin_mirror_repo_id": row.mirror_repo_id,
                            "expected_mirror_repo_id": mirror.id,
                            "reason": "pin_run_wrong_mirror",
                        },
                    )
                if row.status != "ok":
                    raise PinUnusable(
                        f"channel pin run_id={rid} for mirror "
                        f"'{mirror.slug}' has status {row.status!r}; "
                        "every channel pin must reference an 'ok' run "
                        "for --snapshot pinned. Re-pin or use "
                        "--snapshot latest.",
                        {
                            "mirror_slug": mirror.slug,
                            "pinned_run_id": rid,
                            "run_status": row.status,
                            "reason": "pin_run_not_ok",
                        },
                    )

            if len(unique_run_ids) == 1:
                pinned_run_per_mirror[mirror_id] = unique_run_ids[0]
                continue

            # All pin rows are ok. Now check manifest-sha conflict.
            sha_by_run = {
                r.id: r.manifest_sha256 for r in run_rows if r.manifest_sha256
            }
            unique_shas = sorted(set(sha_by_run.values()))
            if len(unique_shas) > 1:
                raise ConflictingPins(
                    f"mirror '{mirror.slug}' is pinned to multiple distinct "
                    "manifest sha256 values across the selected profiles' "
                    "channels; a bundle exports one byte snapshot per "
                    "mirror, so this can't be reconciled. Re-pin so all "
                    "channels referencing this mirror agree.",
                    {
                        "mirror_slug": mirror.slug,
                        "pinned_run_ids": unique_run_ids,
                        "manifest_sha256_by_run_id": sha_by_run,
                        "distinct_manifest_sha256_count": len(unique_shas),
                    },
                )
            # All pins resolve to the same sha.
            # pick the most-recent ok row by ``started_at`` (closer
            # to live) instead of the smallest run_id. Functionally
            # equivalent today since the canonicalizer downstream
            # rewrites byte-equivalent picks to latest-ok, but
            # matches the "closest to live" intuition and stays
            # robust if the canonicalizer becomes opt-out later.
            # Secondary sort by id makes the tiebreak
            # deterministic when two pins share a started_at.
            chosen = max(run_rows, key=lambda r: (r.started_at, r.id))
            pinned_run_per_mirror[mirror_id] = chosen.id

        # Validate that every override slug references a mirror in scope.
        slug_to_mirror_id = {m.slug: mid for mid, m in mirror_ids_seen.items()}
        for slug in overrides:
            if slug not in slug_to_mirror_id:
                raise UnknownOverrideMirror(
                    f"snapshot override references mirror '{slug}' which "
                    "is not composed by any selected profile/channel",
                    {
                        "override_slug": slug,
                        "in_scope_mirror_slugs": sorted(slug_to_mirror_id.keys()),
                    },
                )

        picks: List[_MirrorPick] = []
        for mirror_id, mirror in mirror_ids_seen.items():
            run = self._select_run_for_mirror(
                mirror=mirror,
                base=base,
                pinned_run_id=pinned_run_per_mirror.get(mirror_id),
                explicit_run_id=overrides.get(mirror.slug),
            )
            # When the picked run is byte-equivalent to the
            # latest-ok run, rewrite to the latest-ok row id so the
            # descriptor's run_id reflects what actually lives on
            # disk. ``_validate_bytes_match_live`` either returns the
            # canonical run or raises.
            run = self._validate_and_canonicalize_run(mirror=mirror, selected_run=run)

            # Collect the channel repo links pointing at this mirror so
            # the descriptor's channel/repo section reflects every
            # path through which the mirror was reached.
            channel_repo_rows = (
                self.db.query(ContentChannelRepo, ContentChannel)
                .join(
                    ContentChannel,
                    ContentChannel.id == ContentChannelRepo.channel_id,
                )
                .join(
                    ContentProfileChannel,
                    ContentProfileChannel.channel_id == ContentChannelRepo.channel_id,
                )
                .filter(
                    ContentChannelRepo.mirror_id == mirror.id,
                    ContentChannel.deleted_at.is_(None),
                    ContentProfileChannel.profile_id.in_([p.id for p in profiles]),
                )
                .order_by(ContentChannel.slug, ContentChannelRepo.id)
                .all()
            )
            picks.append(
                _MirrorPick(
                    mirror=mirror,
                    run=run,
                    channel_repos=channel_repo_rows,
                    pinned_for_any_channel=any(
                        r.pinned_run_id is not None for r, _ in channel_repo_rows
                    ),
                )
            )

        # Stable ordering by mirror slug for deterministic descriptor.
        picks.sort(key=lambda p: p.mirror.slug)
        return picks

    def _select_run_for_mirror(
        self,
        *,
        mirror: MirrorRepo,
        base: str,
        pinned_run_id: Optional[int],
        explicit_run_id: Optional[int],
    ) -> MirrorSyncRun:
        """Return the chosen run row for ``mirror``.

        Order of precedence (PRA-160 design lock, refined #1-a):
          1. Explicit per-mirror override.
          2. ``base='pinned'`` + a pin exists on any channel using
             this mirror — the pin row MUST exist and be
             ``status='ok'`` or we refuse with ``PinUnusable``. No
             silent fallback to latest: the
             operator's intent was "ship the pinned snapshot", and a
             surprise downgrade to latest is too easy to miss.
          3. ``base='latest'`` (or ``base='pinned'`` with no pin
             present on any channel referencing this mirror) →
             latest ``status='ok'`` run.

        Validates that the chosen run belongs to ``mirror`` and is
        ``status='ok'``. Refuses with ``InvalidOverrideRun`` /
        ``PinUnusable`` / ``NoSnapshotAvailable`` otherwise.
        """
        if explicit_run_id is not None:
            run = (
                self.db.query(MirrorSyncRun)
                .filter(MirrorSyncRun.id == explicit_run_id)
                .one_or_none()
            )
            if run is None or run.mirror_repo_id != mirror.id:
                raise InvalidOverrideRun(
                    f"override run_id={explicit_run_id} does not belong to "
                    f"mirror '{mirror.slug}'",
                    {
                        "mirror_slug": mirror.slug,
                        "override_run_id": explicit_run_id,
                    },
                )
            if run.status != "ok":
                raise InvalidOverrideRun(
                    f"override run_id={explicit_run_id} for mirror "
                    f"'{mirror.slug}' has status {run.status!r}; only 'ok' "
                    "runs are exportable",
                    {
                        "mirror_slug": mirror.slug,
                        "override_run_id": explicit_run_id,
                        "run_status": run.status,
                    },
                )
            return run

        if base == "pinned" and pinned_run_id is not None:
            run = (
                self.db.query(MirrorSyncRun)
                .filter(MirrorSyncRun.id == pinned_run_id)
                .one_or_none()
            )
            if run is None:
                raise PinUnusable(
                    f"channel pin run_id={pinned_run_id} for mirror "
                    f"'{mirror.slug}' references a missing run row; "
                    "re-pin to a current snapshot or use --snapshot latest",
                    {
                        "mirror_slug": mirror.slug,
                        "pinned_run_id": pinned_run_id,
                        "reason": "pin_run_missing",
                    },
                )
            if run.status != "ok":
                raise PinUnusable(
                    f"channel pin run_id={pinned_run_id} for mirror "
                    f"'{mirror.slug}' has status {run.status!r}; only 'ok' "
                    "runs are exportable. Re-pin or use --snapshot latest.",
                    {
                        "mirror_slug": mirror.slug,
                        "pinned_run_id": pinned_run_id,
                        "run_status": run.status,
                        "reason": "pin_run_not_ok",
                    },
                )
            return run

        latest = (
            self.db.query(MirrorSyncRun)
            .filter(
                MirrorSyncRun.mirror_repo_id == mirror.id,
                MirrorSyncRun.status == "ok",
            )
            .order_by(MirrorSyncRun.started_at.desc())
            .first()
        )
        if latest is None:
            raise NoSnapshotAvailable(
                f"mirror '{mirror.slug}' has no successful sync run; "
                "nothing to export",
                {"mirror_slug": mirror.slug},
            )
        return latest

    def _validate_and_canonicalize_run(
        self, *, mirror: MirrorRepo, selected_run: MirrorSyncRun
    ) -> MirrorSyncRun:
        """Validate that the selected run's bytes are exportable AND
        rewrite to the canonical (latest-ok) run row when
        byte-equivalent.

        PRA-157 ``live/`` is always last-promoted. The latest
        ``status='ok'`` run row's ``manifest_sha256`` is the manifest
        of what's currently on disk. If the planner picked a
        different run (pinned, override, conflicting-but-equivalent
        pins), its bytes are not retained — refuse with
        ``HistoricalBytesUnavailable``.

        When the manifest_sha256 matches but the row
        ids differ (e.g. a no-op incremental sync produced an
        identical tree, or an older pin happens to byte-equal live),
        rewrite the picked run to ``latest_ok`` so the descriptor's
        ``run_id`` reflects the row that actually lives on disk.
        Imported provenance then aligns with the live tree being
        exported instead of trailing through stale row ids.
        """
        latest_ok = (
            self.db.query(MirrorSyncRun)
            .filter(
                MirrorSyncRun.mirror_repo_id == mirror.id,
                MirrorSyncRun.status == "ok",
            )
            .order_by(MirrorSyncRun.started_at.desc())
            .first()
        )
        # latest_ok existence already enforced by ``_select_run_for_mirror``
        # via NoSnapshotAvailable; reaching here means there's at
        # least one ok run.
        assert latest_ok is not None
        if latest_ok.id == selected_run.id:
            return selected_run

        if (
            selected_run.manifest_sha256 is not None
            and latest_ok.manifest_sha256 is not None
            and selected_run.manifest_sha256 == latest_ok.manifest_sha256
        ):
            # Byte-equivalent. Canonicalize to latest-ok so the
            # descriptor's run_id matches live.
            return latest_ok

        raise HistoricalBytesUnavailable(
            f"selected run id={selected_run.id} for mirror '{mirror.slug}' "
            f"has manifest_sha256 {selected_run.manifest_sha256!r} but the "
            f"current live tree reflects run id={latest_ok.id} with "
            f"manifest_sha256 {latest_ok.manifest_sha256!r}; PRA-157 does "
            "not retain historical bytes, so this snapshot cannot be "
            "exported. Either accept --snapshot latest, re-pin to the "
            "current run, or wait for the desired snapshot to become "
            "live again.",
            {
                "mirror_slug": mirror.slug,
                "requested_run_id": selected_run.id,
                "requested_manifest_sha256": selected_run.manifest_sha256,
                "current_live_run_id": latest_ok.id,
                "current_live_manifest_sha256": latest_ok.manifest_sha256,
                "reason": "historical bytes not retained",
            },
        )

    # ------------------------------------------------------------------
    # Step 3: descriptor assembly
    # ------------------------------------------------------------------

    def _build_descriptor(
        self,
        *,
        profiles: List[ContentProfile],
        mirror_picks: List[_MirrorPick],
        kind: str,
        parent_bundle_id: Optional[str],
        bundle_signing_fingerprint: str,
        package_family: str,
    ) -> BundleDescriptor:
        from ..content_profile_service import (  # pylint: disable=import-outside-toplevel
            _decode_string_list,
        )

        bundle_id = str(uuid.uuid4())

        # Build profile descriptors.
        profile_descriptors: List[ProfileDescriptor] = []
        for profile in profiles:
            channel_links = (
                self.db.query(ContentProfileChannel, ContentChannel)
                .join(
                    ContentChannel,
                    ContentChannel.id == ContentProfileChannel.channel_id,
                )
                .filter(
                    ContentProfileChannel.profile_id == profile.id,
                    ContentChannel.deleted_at.is_(None),
                )
                .order_by(ContentChannel.slug)
                .all()
            )
            profile_descriptors.append(
                ProfileDescriptor(
                    slug=profile.slug,
                    display_name=profile.display_name,
                    package_family=profile.package_family,
                    description=profile.description,
                    channel_slugs=[c.slug for _, c in channel_links],
                )
            )

        # Build channel descriptors. Walk every channel referenced by
        # any selected profile so the descriptor section is exactly
        # what the importer needs to recreate channels.
        seen_channel_ids: Dict[int, ContentChannel] = {}
        for profile in profiles:
            rows = (
                self.db.query(ContentChannel)
                .join(
                    ContentProfileChannel,
                    ContentProfileChannel.channel_id == ContentChannel.id,
                )
                .filter(
                    ContentProfileChannel.profile_id == profile.id,
                    ContentChannel.deleted_at.is_(None),
                )
                .all()
            )
            for c in rows:
                seen_channel_ids[c.id] = c

        channel_descriptors: List[ChannelDescriptor] = []
        # Index channel_repos by channel_id for the descriptor build.
        for cid, channel in sorted(seen_channel_ids.items(), key=lambda kv: kv[1].slug):
            repo_rows = (
                self.db.query(ContentChannelRepo, MirrorRepo)
                .join(MirrorRepo, MirrorRepo.id == ContentChannelRepo.mirror_id)
                .filter(
                    ContentChannelRepo.channel_id == channel.id,
                    MirrorRepo.deleted_at.is_(None),
                )
                .order_by(MirrorRepo.slug, ContentChannelRepo.id)
                .all()
            )
            # Pinned-run sha256 fan-out.
            pin_ids = [
                repo.pinned_run_id for repo, _ in repo_rows if repo.pinned_run_id
            ]
            pin_index: Dict[int, str] = {}
            if pin_ids:
                for run in (
                    self.db.query(MirrorSyncRun)
                    .filter(MirrorSyncRun.id.in_(pin_ids))
                    .all()
                ):
                    if run.manifest_sha256 is not None:
                        pin_index[run.id] = run.manifest_sha256
            channel_descriptors.append(
                ChannelDescriptor(
                    slug=channel.slug,
                    display_name=channel.display_name,
                    package_family=channel.package_family,
                    description=channel.description,
                    repos=[
                        ChannelRepoDescriptor(
                            mirror_slug=mirror.slug,
                            suite_override=repo.suite_override,
                            pinned_run_id=repo.pinned_run_id,
                            pinned_manifest_sha256=(
                                pin_index.get(repo.pinned_run_id)
                                if repo.pinned_run_id is not None
                                else None
                            ),
                        )
                        for repo, mirror in repo_rows
                    ],
                )
            )

        # Build mirror descriptors with per-mirror signing key fan-out.
        mirror_descriptors: List[MirrorRunDescriptor] = []
        for pick in mirror_picks:
            mirror = pick.mirror
            run = pick.run
            keys = (
                self.db.query(MirrorSigningKey)
                .filter(
                    MirrorSigningKey.mirror_repo_id == mirror.id,
                    MirrorSigningKey.status.in_(
                        ("active", "pending_cutover", "rotating_out")
                    ),
                )
                .all()
            )
            fingerprints: List[str] = []
            armored: List[str] = []
            for k in keys:
                # Read armored material via the cached column (PRA-158
                # #3a). Descriptor build MUST NOT pull private material
                # from Vault — it's a public-only read path.
                #
                # Any key whose armored bytes are empty
                # gets dropped from the declared set BEFORE the
                # missing-material refusal below. If that drops the
                # set to empty, we refuse rather than ship a
                # signed-but-unverifiable bundle. The importer trusts
                # only keys declared inside the (signed) descriptor,
                # so an empty declared set means manifest sigs can't
                # be verified offline.
                if not k.armored_public_key:
                    logger.warning(
                        "mirror '%s' signing key fingerprint=%s has no "
                        "cached armored_public_key; dropping from "
                        "descriptor declared-key set. Operator should "
                        "rerun trust-bundle distribution to populate "
                        "the column before exporting.",
                        mirror.slug,
                        k.gpg_fingerprint,
                    )
                    continue
                fingerprints.append(k.gpg_fingerprint)
                armored.append(k.armored_public_key)

            if not fingerprints:
                raise MirrorSigningMaterialMissing(
                    f"mirror '{mirror.slug}' has no usable armored public "
                    "key material declared for its manifest signer; the "
                    "bundle would be signed-but-unverifiable for this "
                    "mirror. Run the trust-bundle distribution path "
                    "(POST /mirrors/{id}/signing-key, or PRA-158 "
                    "rotate-prepare/cutover) to populate signing keys "
                    "before exporting.",
                    {
                        "mirror_slug": mirror.slug,
                        "reason": "no_armored_public_keys",
                    },
                )

            mirror_descriptors.append(
                MirrorRunDescriptor(
                    mirror_slug=mirror.slug,
                    package_family=mirror.package_family,
                    distribution=mirror.distribution,
                    components=_decode_string_list(mirror.components),
                    architectures=_decode_string_list(mirror.architectures),
                    run_id=run.id,
                    manifest_sha256=run.manifest_sha256 or "",
                    manifest_path=run.manifest_path or "",
                    byte_count=run.byte_count,
                    package_count=run.package_count,
                    signing_key_fingerprints=fingerprints,
                    signing_keys_armored=armored,
                )
            )

        return BundleDescriptor(
            bundle_version=BUNDLE_SCHEMA_VERSION,
            bundle_id=bundle_id,
            kind=kind,
            parent_bundle_id=parent_bundle_id,
            created_at=datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            praxis_instance_signing_fingerprint=bundle_signing_fingerprint,
            profiles=profile_descriptors,
            channels=channel_descriptors,
            mirrors=mirror_descriptors,
        )


def serialize_request_for_audit(
    *,
    profile_slugs: List[str],
    snapshot_selector_base: str,
    snapshot_overrides: Optional[Dict[str, int]],
    kind: str,
    parent_bundle_id: Optional[str],
) -> str:
    """Stable JSON body for ``airgap_bundles.request_payload``.

    Sorted keys + UTF-8; readable when an admin queries the row in
    psql.
    """
    return json.dumps(
        {
            "profile_slugs": profile_slugs,
            "snapshot_selector_base": snapshot_selector_base,
            "snapshot_overrides": snapshot_overrides or {},
            "kind": kind,
            "parent_bundle_id": parent_bundle_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
