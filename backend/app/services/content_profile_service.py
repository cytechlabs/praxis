"""Content-profile resolution + CRUD validation (PRA-159 slice #1).

The headline primitive is :func:`ContentProfileService.resolve_effective`
— it walks a host's three subscription tiers (direct → static-group →
smart-group) with strict precedence and returns one of three states:

    no_profile   — host has zero subscriptions across all tiers.
    resolved     — exactly one profile wins at the highest non-empty
                   tier. Apply orchestrator (slice #3) writes
                   ``/etc/.../praxis-profile-<slug>.{list,repo}``.
    conflict     — two or more distinct profiles tie at the highest
                   non-empty tier. Apply orchestrator MUST refuse;
                   resolver returns the contributing bindings so
                   operators can see ambiguity loud and resolve it
                   manually.

Why precedence + tier-internal conflict (rather than auto-resolution):
locked in the PRA-159 scoping conversation. Alphabetical / most-recent
/ priority-field auto-resolution all hide intent and create policy
surface. The clean v1 contract is "one profile per host or operator
fixes it."

Soft-deleted profiles (``deleted_at IS NOT NULL``) are filtered out
of every tier — they exist for audit history but never participate
in resolution. A subscription whose profile is soft-deleted is
effectively dormant; we don't auto-clean the row because the
operator may un-delete the profile.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import List, Literal, Optional, Tuple

from sqlalchemy.orm import Session

from ..db.models import (
    ContentChannel,
    ContentChannelRepo,
    ContentProfile,
    ContentProfileChannel,
    Group,
    GroupContentProfileSubscription,
    HostContentProfileSubscription,
    MirrorRepo,
    MirrorSyncRun,
    SmartGroup,
    SmartGroupContentProfileSubscription,
    SmartGroupMembership,
    System,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result shapes (transport-neutral; route layer adapts to Pydantic)
# ---------------------------------------------------------------------------


ResolutionState = Literal["no_profile", "resolved", "conflict"]
ViaKind = Literal["direct", "group", "smart_group"]


@dataclass(frozen=True)
class ResolvedBinding:
    """One subscription that contributed to (or conflicted at) the
    resolved tier.

    ``via_id`` and ``via_label`` are ``None`` for the ``direct`` kind
    (the binding IS the host) and populated for group / smart-group
    kinds with the originating group's id + name.
    """

    profile_id: int
    profile_slug: str
    profile_display_name: str
    via_kind: ViaKind
    via_id: Optional[int]
    via_label: Optional[str]


@dataclass(frozen=True)
class EffectiveProfile:
    """Three-state resolver output. See module docstring."""

    state: ResolutionState
    profile: Optional[ResolvedBinding]
    conflict_bindings: List[ResolvedBinding]


@dataclass(frozen=True)
class ResolvedMirrorEntry:
    """One ``(channel, mirror, suite, components, architectures, pin)``
    tuple in the resolved fan-out for a profile (PRA-159 slice #2).

    Source-list generation (slice #3) iterates these to emit one
    line/stanza per entry. Each entry references the upstream by
    ``mirror_slug`` and resolves the effective suite once
    (``suite_override`` if set, else the mirror's own
    ``distribution``). ``pinned_run_id`` and
    ``pinned_manifest_sha256`` are non-null when a tracking pin is
    set; bytes still come from the mirror's ``live/`` tree per the
    PRA-159 lock — pin is metadata-only.
    """

    channel_id: int
    channel_slug: str
    mirror_id: int
    mirror_slug: str
    package_family: str
    suite: str
    components: List[str]
    architectures: List[str]
    pinned_run_id: Optional[int]
    pinned_manifest_sha256: Optional[str]


@dataclass(frozen=True)
class ResolvedContent:
    """Effective profile + flattened mirror entries (PRA-159 slice #2).

    State mirrors ``EffectiveProfile.state``:
      * ``no_profile`` / ``conflict`` — entries is empty; caller must
        not generate source config.
      * ``resolved`` — entries is the canonical set the host will
        receive when slice #3's apply orchestrator runs.
    """

    state: ResolutionState
    profile: Optional[ResolvedBinding]
    conflict_bindings: List[ResolvedBinding]
    entries: List[ResolvedMirrorEntry]


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class ContentProfileError(Exception):
    """Domain error from the profile/channel CRUD surface.

    Route layer maps to 400/409 as appropriate; the service raises
    this rather than a route-bound HTTPException so the resolver can
    be reused from the apply orchestrator (slice #3) without
    pretending an HTTP context exists.
    """


class ContentProfileService:
    """Resolution + cross-table validation for the profile/channel layer.

    CRUD persistence is done directly in the route handlers (matching
    the pattern in ``mirrors.py`` / ``mirror_upstream_keys.py``); this
    service exposes the operations whose semantics span tables OR
    that need to be reused from non-route call sites (apply
    orchestrator, smart-group recompute hook, cutover-preview).
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    # ---- resolution -------------------------------------------------------

    def resolve_effective(self, host_id: int) -> EffectiveProfile:
        """Resolve the effective profile for ``host_id``.

        Tier precedence is strict:

          1. ``HostContentProfileSubscription`` (direct).
          2. Else ``GroupContentProfileSubscription`` for the host's
             ``System.group_id`` (NULL group means tier is empty for
             this host — skip).
          3. Else ``SmartGroupContentProfileSubscription`` for every
             smart group whose membership cache contains the host.

        At each tier we compute the set of *distinct profile ids*. If
        the set is empty, fall through. If it has exactly one profile,
        return ``resolved``. If two or more, return ``conflict`` with
        every contributing binding for that tier (lower tiers do NOT
        appear in conflict output — precedence is strict).

        Soft-deleted profiles are filtered out of every tier query;
        a subscription pointing at a soft-deleted profile is dormant.
        """
        host = self.db.query(System).filter(System.id == host_id).one_or_none()
        if host is None:
            # Caller should 404 before getting here, but be defensive
            # — apply orchestrator may pass a host id that's been
            # deleted between fetch and resolve.
            return EffectiveProfile(
                state="no_profile", profile=None, conflict_bindings=[]
            )

        # Tier 1: direct
        direct = self._direct_bindings(host_id)
        decision = self._tier_decision(direct)
        if decision is not None:
            return decision

        # Tier 2: static group (only if host has one)
        if host.group_id is not None:
            group_bindings = self._group_bindings(host.group_id)
            decision = self._tier_decision(group_bindings)
            if decision is not None:
                return decision

        # Tier 3: smart groups (every smart group whose membership
        # cache contains the host).
        smart_bindings = self._smart_group_bindings(host_id)
        decision = self._tier_decision(smart_bindings)
        if decision is not None:
            return decision

        return EffectiveProfile(state="no_profile", profile=None, conflict_bindings=[])

    def _tier_decision(
        self, bindings: List[ResolvedBinding]
    ) -> Optional[EffectiveProfile]:
        """Apply the tier-internal rule.

        ``None`` means the tier is empty — caller should fall through
        to the next tier.
        """
        if not bindings:
            return None

        distinct_profile_ids = {b.profile_id for b in bindings}
        if len(distinct_profile_ids) == 1:
            # One profile — but possibly multiple bindings (e.g. host is
            # in two groups both subscribed to the same profile).
            # Surface the first binding deterministically (smallest id).
            chosen = sorted(bindings, key=lambda b: (b.profile_id, b.via_id or 0))[0]
            return EffectiveProfile(
                state="resolved", profile=chosen, conflict_bindings=[]
            )

        return EffectiveProfile(
            state="conflict",
            profile=None,
            conflict_bindings=sorted(
                bindings,
                key=lambda b: (b.profile_id, b.via_kind, b.via_id or 0),
            ),
        )

    # ---- per-tier binding extractors --------------------------------------

    def _direct_bindings(self, host_id: int) -> List[ResolvedBinding]:
        rows = (
            self.db.query(
                HostContentProfileSubscription.profile_id,
                ContentProfile.slug,
                ContentProfile.display_name,
            )
            .join(
                ContentProfile,
                ContentProfile.id == HostContentProfileSubscription.profile_id,
            )
            .filter(
                HostContentProfileSubscription.host_id == host_id,
                ContentProfile.deleted_at.is_(None),
            )
            .all()
        )
        return [
            ResolvedBinding(
                profile_id=r[0],
                profile_slug=r[1],
                profile_display_name=r[2],
                via_kind="direct",
                via_id=None,
                via_label=None,
            )
            for r in rows
        ]

    def _group_bindings(self, group_id: int) -> List[ResolvedBinding]:
        rows = (
            self.db.query(
                GroupContentProfileSubscription.profile_id,
                ContentProfile.slug,
                ContentProfile.display_name,
                Group.id,
                Group.name,
            )
            .join(
                ContentProfile,
                ContentProfile.id == GroupContentProfileSubscription.profile_id,
            )
            .join(Group, Group.id == GroupContentProfileSubscription.group_id)
            .filter(
                GroupContentProfileSubscription.group_id == group_id,
                ContentProfile.deleted_at.is_(None),
            )
            .all()
        )
        return [
            ResolvedBinding(
                profile_id=r[0],
                profile_slug=r[1],
                profile_display_name=r[2],
                via_kind="group",
                via_id=r[3],
                via_label=r[4],
            )
            for r in rows
        ]

    def _smart_group_bindings(self, host_id: int) -> List[ResolvedBinding]:
        rows = (
            self.db.query(
                SmartGroupContentProfileSubscription.profile_id,
                ContentProfile.slug,
                ContentProfile.display_name,
                SmartGroup.id,
                SmartGroup.name,
            )
            .join(
                ContentProfile,
                ContentProfile.id == SmartGroupContentProfileSubscription.profile_id,
            )
            .join(
                SmartGroup,
                SmartGroup.id == SmartGroupContentProfileSubscription.smart_group_id,
            )
            .join(
                SmartGroupMembership,
                SmartGroupMembership.smart_group_id == SmartGroup.id,
            )
            .filter(
                SmartGroupMembership.system_id == host_id,
                ContentProfile.deleted_at.is_(None),
                SmartGroup.enabled.is_(True),
            )
            .all()
        )
        return [
            ResolvedBinding(
                profile_id=r[0],
                profile_slug=r[1],
                profile_display_name=r[2],
                via_kind="smart_group",
                via_id=r[3],
                via_label=r[4],
            )
            for r in rows
        ]

    # ---- cross-table validation helpers (used by the route layer) --------

    def assert_profile_channel_family_match(
        self, profile: ContentProfile, channel_package_family: str
    ) -> None:
        """Refuse linking a channel of a different ``package_family``
        to a profile.

        A profile generates one source-list file per host (one .list
        for deb, one .repo for rpm); mixing families would force
        Praxis to emit two file kinds from one profile and break the
        resolver's "one file per profile per host" contract.
        """
        if profile.package_family != channel_package_family:
            raise ContentProfileError(
                f"Profile package_family={profile.package_family!r} cannot "
                f"compose a channel of package_family="
                f"{channel_package_family!r}"
            )

    @staticmethod
    def assert_channel_repo_family_match(
        channel_package_family: str, mirror_package_family: str
    ) -> None:
        """Refuse adding a mirror of a different ``package_family``
        to a channel."""
        if channel_package_family != mirror_package_family:
            raise ContentProfileError(
                f"Channel package_family={channel_package_family!r} cannot "
                f"include a mirror of package_family="
                f"{mirror_package_family!r}"
            )

    def assert_pinned_run_belongs_to_mirror(
        self, run_id: int, mirror_id: int
    ) -> Tuple[str, str]:
        """Validate ``pinned_run_id`` references an ``ok`` run on
        ``mirror_id``.

        Returns ``(manifest_sha256, manifest_path)`` for use in
        downstream UI/diff payloads. Raises ``ContentProfileError``
        on any mismatch (wrong mirror, run missing, status != 'ok',
        manifest fields null).
        """
        # Lazy import to avoid widening models.py's blast radius from
        # this service module.
        from ..db.models import MirrorSyncRun

        run = (
            self.db.query(MirrorSyncRun)
            .filter(MirrorSyncRun.id == run_id)
            .one_or_none()
        )
        if run is None:
            raise ContentProfileError(f"pinned_run_id {run_id} not found")
        if run.mirror_repo_id != mirror_id:
            raise ContentProfileError(
                f"pinned_run_id {run_id} belongs to mirror "
                f"{run.mirror_repo_id}, not {mirror_id}"
            )
        if run.status != "ok":
            raise ContentProfileError(
                f"pinned_run_id {run_id} has status={run.status!r}; only "
                "'ok' runs may be pinned"
            )
        if run.manifest_sha256 is None or run.manifest_path is None:
            # Service-level invariant from PRA-157 — shouldn't happen
            # for ok rows, but defend so a corrupt row can't slip a
            # half-baked pin into the channel.
            raise ContentProfileError(
                f"pinned_run_id {run_id} is missing manifest fields; " "refuse pin"
            )
        return run.manifest_sha256, run.manifest_path

    # ---- mirror-entry resolution (slice #2) ------------------------------

    def resolve_mirror_entries_for_profile(
        self, profile_id: int
    ) -> List[ResolvedMirrorEntry]:
        """Flatten ``profile -> channels -> repos`` into the canonical
        mirror-entry set source-list generation will iterate.

        Soft-deleted channels are filtered out (operator may have
        retired a channel without removing every profile link;
        resolver treats it as dormant).

        ``components`` and ``architectures`` come from the underlying
        ``MirrorRepo`` (channel-level filters are deferred per the
        PRA-159 lock — v1 channels are full-suite + components +
        architectures selection only). ``suite`` is
        ``content_channel_repos.suite_override`` if set, else the
        mirror's own ``distribution``.

        Pinned manifest sha is loaded from the referenced
        ``mirror_sync_runs`` row when ``pinned_run_id`` is set.
        """
        rows = (
            self.db.query(ContentChannelRepo, ContentChannel, MirrorRepo)
            .join(
                ContentProfileChannel,
                ContentProfileChannel.channel_id == ContentChannelRepo.channel_id,
            )
            .join(ContentChannel, ContentChannel.id == ContentChannelRepo.channel_id)
            .join(MirrorRepo, MirrorRepo.id == ContentChannelRepo.mirror_id)
            .filter(
                ContentProfileChannel.profile_id == profile_id,
                ContentChannel.deleted_at.is_(None),
                MirrorRepo.deleted_at.is_(None),
            )
            .order_by(ContentChannel.slug, MirrorRepo.slug, ContentChannelRepo.id)
            .all()
        )

        # Bulk-fetch any pinned-run manifest fingerprints in one query
        # so a profile with N pins doesn't issue N+1 reads.
        pin_ids = [r.pinned_run_id for r, _, _ in rows if r.pinned_run_id is not None]
        pin_index: dict[int, str] = {}
        if pin_ids:
            for run in (
                self.db.query(MirrorSyncRun).filter(MirrorSyncRun.id.in_(pin_ids)).all()
            ):
                if run.manifest_sha256 is not None:
                    pin_index[run.id] = run.manifest_sha256

        out: List[ResolvedMirrorEntry] = []
        for repo_link, channel, mirror in rows:
            out.append(
                ResolvedMirrorEntry(
                    channel_id=channel.id,
                    channel_slug=channel.slug,
                    mirror_id=mirror.id,
                    mirror_slug=mirror.slug,
                    package_family=mirror.package_family,
                    suite=repo_link.suite_override or mirror.distribution,
                    components=_decode_string_list(mirror.components),
                    architectures=_decode_string_list(mirror.architectures),
                    pinned_run_id=repo_link.pinned_run_id,
                    pinned_manifest_sha256=(
                        pin_index.get(repo_link.pinned_run_id)
                        if repo_link.pinned_run_id is not None
                        else None
                    ),
                )
            )
        return out

    def resolve_content_for_host(self, host_id: int) -> ResolvedContent:
        """Combine ``resolve_effective`` with mirror-entry fan-out.

        ``no_profile`` / ``conflict`` → ``entries`` is empty. Slice
        #3's apply orchestrator MUST refuse to write source config in
        either of those states — the empty entries list is the
        belt-and-braces signal.
        """
        effective = self.resolve_effective(host_id)
        if effective.state != "resolved" or effective.profile is None:
            return ResolvedContent(
                state=effective.state,
                profile=effective.profile,
                conflict_bindings=effective.conflict_bindings,
                entries=[],
            )
        entries = self.resolve_mirror_entries_for_profile(effective.profile.profile_id)
        return ResolvedContent(
            state="resolved",
            profile=effective.profile,
            conflict_bindings=[],
            entries=entries,
        )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _decode_string_list(raw: Optional[str]) -> List[str]:
    """Decode a JSON-encoded text column as a list of strings.

    Mirror ``components`` and ``architectures`` are stored as JSON
    text in ``mirror_repos`` (PRA-157 schema choice). Resolver needs
    them as plain ``list[str]`` for source-list emission and diff
    grouping. Mirrors the same helper in ``app/api/routes/mirrors.py``;
    duplicated here so the service module doesn't depend on the route
    module's import surface.
    """
    if raw is None or raw == "":
        return []
    try:
        decoded = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return []
    if not isinstance(decoded, list):
        return []
    return [item for item in decoded if isinstance(item, str)]
