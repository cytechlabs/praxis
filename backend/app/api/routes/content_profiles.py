"""Content profile CRUD + channel-composition + subscriptions
+ effective resolution (PRA-159 slice #1).

Mounts at ``/content-profiles``. Profiles are the host-facing object
— hosts subscribe via direct / static-group / smart-group bindings,
and ``ContentProfileService.resolve_effective`` returns one of
``no_profile | resolved | conflict`` per host. The resolver is also
exposed via ``GET /systems/{id}/content-profile`` (mounted by
``main.py`` via ``content_profile_systems_router``) so the host
detail page can show ambiguity before an operator clicks Apply.

Route ordering note (``feedback_fastapi_route_ordering.md``): all
sub-resource paths are declared BEFORE bare ``/{profile_id}``.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.schemas.content_profiles import (
    ContentProfileCreate,
    ContentProfileRead,
    ContentProfileUpdate,
    EffectiveProfileBindingRead,
    EffectiveProfileRead,
    ProfileChannelAdd,
    ProfileGroupSubscriptionAdd,
    ProfileHostSubscriptionAdd,
    ProfileSmartGroupSubscriptionAdd,
    ProfileSubscriberRead,
    SubscriptionRead,
)
from app.api.schemas.content_serve import (
    ProfileDiffRead,
    ProfileManifestRead,
    ResolvedContentRead,
    ResolvedMirrorEntryRead,
)
from app.core.auth import get_current_user, require_role
from app.db.models import (
    ContentChannel,
    ContentProfile,
    ContentProfileChannel,
    Group,
    GroupContentProfileSubscription,
    HostContentProfileSubscription,
    SmartGroup,
    SmartGroupContentProfileSubscription,
    System,
)
from app.db.session import get_db
from app.services import audit_event_service
from app.services.access_authorization_service import (
    scope_query_by_system,
    scoped_system_ids,
)
from app.services.content_profile_diff import (
    compute_profile_diff,
    compute_profile_manifest,
)
from app.services.content_profile_service import (
    ContentProfileError,
    ContentProfileService,
    EffectiveProfile,
    ResolvedBinding,
    ResolvedMirrorEntry,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["content-profiles"])

# Separate router mounted under /systems by main.py for the
# host-detail effective-profile read.
systems_router = APIRouter(tags=["content-profiles"])


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _profile_to_read(profile: ContentProfile, db: Session) -> dict:
    links = (
        db.query(ContentProfileChannel, ContentChannel)
        .join(ContentChannel, ContentChannel.id == ContentProfileChannel.channel_id)
        .filter(ContentProfileChannel.profile_id == profile.id)
        .order_by(ContentChannel.slug)
        .all()
    )
    return {
        "id": profile.id,
        "slug": profile.slug,
        "display_name": profile.display_name,
        "package_family": profile.package_family,
        "description": profile.description,
        "deleted_at": profile.deleted_at,
        "created_at": profile.created_at,
        "updated_at": profile.updated_at,
        "channels": [
            {
                "id": link.id,
                "channel_id": ch.id,
                "channel_slug": ch.slug,
                "channel_display_name": ch.display_name,
            }
            for link, ch in links
        ],
    }


def _resolved_entry_to_dict(entry: ResolvedMirrorEntry) -> dict:
    return {
        "channel_id": entry.channel_id,
        "channel_slug": entry.channel_slug,
        "mirror_id": entry.mirror_id,
        "mirror_slug": entry.mirror_slug,
        "package_family": entry.package_family,
        "suite": entry.suite,
        "components": entry.components,
        "architectures": entry.architectures,
        "pinned_run_id": entry.pinned_run_id,
        "pinned_manifest_sha256": entry.pinned_manifest_sha256,
    }


def _binding_to_read(binding: ResolvedBinding) -> dict:
    return {
        "profile_id": binding.profile_id,
        "profile_slug": binding.profile_slug,
        "profile_display_name": binding.profile_display_name,
        "via_kind": binding.via_kind,
        "via_id": binding.via_id,
        "via_label": binding.via_label,
    }


def _effective_to_read(effective: EffectiveProfile) -> dict:
    return {
        "state": effective.state,
        "profile": _binding_to_read(effective.profile)
        if effective.profile is not None
        else None,
        "conflict_bindings": [_binding_to_read(b) for b in effective.conflict_bindings],
    }


def _live_or_404(
    db: Session, profile_id: int, *, include_deleted: bool = False
) -> ContentProfile:
    q = db.query(ContentProfile).filter(ContentProfile.id == profile_id)
    if not include_deleted:
        q = q.filter(ContentProfile.deleted_at.is_(None))
    profile = q.one_or_none()
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Content profile {profile_id} not found",
        )
    return profile


def _live_channel_or_400(db: Session, channel_id: int) -> ContentChannel:
    channel = (
        db.query(ContentChannel)
        .filter(ContentChannel.id == channel_id, ContentChannel.deleted_at.is_(None))
        .one_or_none()
    )
    if channel is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Content channel {channel_id} not found or soft-deleted",
        )
    return channel


def _system_or_400(db: Session, host_id: int) -> System:
    host = db.query(System).filter(System.id == host_id).one_or_none()
    if host is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"System {host_id} not found",
        )
    return host


def _group_or_400(db: Session, group_id: int) -> Group:
    group = db.query(Group).filter(Group.id == group_id).one_or_none()
    if group is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Group {group_id} not found",
        )
    return group


def _smart_group_or_400(db: Session, smart_group_id: int) -> SmartGroup:
    sg = db.query(SmartGroup).filter(SmartGroup.id == smart_group_id).one_or_none()
    if sg is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Smart group {smart_group_id} not found",
        )
    return sg


def _actor_id(current_user) -> Optional[int]:
    return getattr(current_user, "id", None) if current_user is not None else None


# ---------------------------------------------------------------------------
# PRA-281 fleet-scope helpers.
# ---------------------------------------------------------------------------


def _scope_gate_system(db: Session, current_user, system_id: int) -> None:
    """PRA-281: a direct out-of-scope (or empty-scope) or nonexistent host id is a
    non-disclosing 404 — identical either way — placed BEFORE the ``System``
    lookup, ``ContentProfileService`` resolution, subscription lookup, duplicate
    check, DB mutation, audit emission, ``recompute_profile_groups``, or any
    hostname/profile-binding/mirror/error serialization. Tenant-wide admins
    (scope ``None``) are unchanged.
    """
    scope = scoped_system_ids(db, current_user)
    if scope is not None and system_id not in scope:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="System not found"
        )


def _require_tenant_wide(db: Session, current_user, detail: str) -> None:
    """PRA-281: a profile/channel/group/smart-group mutation (or the mixed
    subscription list) alters effective host resolution across the whole fleet and
    triggers ``recompute_profile_groups`` — not attributable to one host. Refuse a
    scoped caller with 403 BEFORE any slug/duplicate check, profile/channel/group/
    smart-group lookup, DB mutation, audit, or recompute. Tenant-wide admins
    unchanged.
    """
    if scoped_system_ids(db, current_user) is not None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def _emit(
    db: Session,
    *,
    action: str,
    profile: ContentProfile,
    context: dict,
) -> None:
    audit_event_service.emit(
        db,
        action=action,
        target_kind="content_profile",
        target_id=str(profile.id),
        context={"profile_slug": profile.slug, **context},
    )
    # PRA-159 #4: every content-profile mutation in this router can
    # change the profile.* smart-group predicate result for one or
    # more hosts (subscription add/remove changes effective binding;
    # channel link changes affect pinned status). Fleet-wide
    # recompute on enabled smart groups whose rule references
    # profile.* — no-op when no such groups exist.
    from app.services.smart_group_service import recompute_profile_groups

    recompute_profile_groups(db)


# ---------------------------------------------------------------------------
# CRUD — list / create at root
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=ContentProfileRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_profile(
    body: ContentProfileCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    _require_tenant_wide(
        db, current_user, "Managing content profiles requires tenant-wide admin access"
    )
    if (
        db.query(ContentProfile).filter(ContentProfile.slug == body.slug).first()
    ) is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Content profile with slug '{body.slug}' already exists",
        )
    profile = ContentProfile(
        slug=body.slug,
        display_name=body.display_name,
        package_family=body.package_family,
        description=body.description,
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)

    _emit(
        db,
        action="content_profile.created",
        profile=profile,
        context={
            "package_family": profile.package_family,
            "display_name": profile.display_name,
            "actor_user_id": _actor_id(current_user),
        },
    )
    logger.info("Created content profile %s (id=%d)", profile.slug, profile.id)
    return _profile_to_read(profile, db)


@router.get("", response_model=List[ContentProfileRead])
async def list_profiles(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
    include_deleted: bool = False,
) -> Any:
    q = db.query(ContentProfile)
    if not include_deleted:
        q = q.filter(ContentProfile.deleted_at.is_(None))
    profiles = q.order_by(ContentProfile.slug).all()
    return [_profile_to_read(p, db) for p in profiles]


# ---------------------------------------------------------------------------
# Sub-resource: profile↔channel composition
# ---------------------------------------------------------------------------


@router.post(
    "/{profile_id}/channels",
    response_model=ContentProfileRead,
    status_code=status.HTTP_201_CREATED,
)
async def add_profile_channel(
    profile_id: int,
    body: ProfileChannelAdd,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    _require_tenant_wide(
        db, current_user, "Managing content profiles requires tenant-wide admin access"
    )
    profile = _live_or_404(db, profile_id)
    channel = _live_channel_or_400(db, body.channel_id)

    service = ContentProfileService(db)
    try:
        service.assert_profile_channel_family_match(profile, channel.package_family)
    except ContentProfileError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    link = ContentProfileChannel(profile_id=profile.id, channel_id=channel.id)
    db.add(link)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Channel {channel.slug!r} is already composed by profile "
                f"{profile.slug!r}"
            ),
        ) from exc

    _emit(
        db,
        action="content_profile.channel_added",
        profile=profile,
        context={
            "channel_id": channel.id,
            "channel_slug": channel.slug,
            "actor_user_id": _actor_id(current_user),
        },
    )
    return _profile_to_read(profile, db)


@router.delete(
    "/{profile_id}/channels/{channel_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_profile_channel(
    profile_id: int,
    channel_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Response:
    _require_tenant_wide(
        db, current_user, "Managing content profiles requires tenant-wide admin access"
    )
    profile = _live_or_404(db, profile_id)
    link = (
        db.query(ContentProfileChannel)
        .filter(
            ContentProfileChannel.profile_id == profile.id,
            ContentProfileChannel.channel_id == channel_id,
        )
        .one_or_none()
    )
    if link is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Channel {channel_id} is not composed by profile " f"{profile.id}"
            ),
        )
    db.delete(link)
    db.commit()

    _emit(
        db,
        action="content_profile.channel_removed",
        profile=profile,
        context={
            "channel_id": channel_id,
            "actor_user_id": _actor_id(current_user),
        },
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Sub-resource: subscriptions (host / group / smart-group)
# ---------------------------------------------------------------------------


def _list_subscriptions(profile: ContentProfile, db: Session) -> List[dict]:
    """Flatten all three subscription tiers into one list shape."""
    out: List[dict] = []

    host_rows = (
        db.query(HostContentProfileSubscription, System.hostname)
        .join(System, System.id == HostContentProfileSubscription.host_id)
        .filter(HostContentProfileSubscription.profile_id == profile.id)
        .all()
    )
    for sub, hostname in host_rows:
        out.append(
            {
                "id": sub.id,
                "profile_id": sub.profile_id,
                "scope_kind": "host",
                "scope_id": sub.host_id,
                "scope_label": hostname,
                "created_at": sub.created_at,
            }
        )

    group_rows = (
        db.query(GroupContentProfileSubscription, Group.name)
        .join(Group, Group.id == GroupContentProfileSubscription.group_id)
        .filter(GroupContentProfileSubscription.profile_id == profile.id)
        .all()
    )
    for sub, gname in group_rows:
        out.append(
            {
                "id": sub.id,
                "profile_id": sub.profile_id,
                "scope_kind": "group",
                "scope_id": sub.group_id,
                "scope_label": gname,
                "created_at": sub.created_at,
            }
        )

    smart_rows = (
        db.query(SmartGroupContentProfileSubscription, SmartGroup.name)
        .join(
            SmartGroup,
            SmartGroup.id == SmartGroupContentProfileSubscription.smart_group_id,
        )
        .filter(SmartGroupContentProfileSubscription.profile_id == profile.id)
        .all()
    )
    for sub, sgname in smart_rows:
        out.append(
            {
                "id": sub.id,
                "profile_id": sub.profile_id,
                "scope_kind": "smart_group",
                "scope_id": sub.smart_group_id,
                "scope_label": sgname,
                "created_at": sub.created_at,
            }
        )

    out.sort(key=lambda r: (r["scope_kind"], r["scope_id"]))
    return out


@router.get(
    "/{profile_id}/subscriptions",
    response_model=List[SubscriptionRead],
)
async def list_profile_subscriptions(
    profile_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Any:
    # PRA-281: the subscription list flattens host (hostname), group, and
    # smart-group binding rows into one mixed set — it would leak hidden hostnames
    # and group/smart-group labels, and a partial per-host filter would be
    # misleading. Tenant-wide-admin-only for scoped callers (documented).
    _require_tenant_wide(
        db,
        current_user,
        "Listing content-profile subscriptions requires tenant-wide admin access",
    )
    profile = _live_or_404(db, profile_id, include_deleted=True)
    return _list_subscriptions(profile, db)


@router.post(
    "/{profile_id}/hosts",
    response_model=SubscriptionRead,
    status_code=status.HTTP_201_CREATED,
)
async def add_host_subscription(
    profile_id: int,
    body: ProfileHostSubscriptionAdd,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    # PRA-281: a direct host subscription is host-derived — scope-gate the host id
    # BEFORE the profile/host lookup, duplicate check, DB insert, audit, recompute,
    # or hostname-bearing response.
    _scope_gate_system(db, current_user, body.host_id)
    profile = _live_or_404(db, profile_id)
    host = _system_or_400(db, body.host_id)
    return _add_subscription(
        db,
        profile=profile,
        scope_kind="host",
        scope_id=host.id,
        scope_label=host.hostname,
        row=HostContentProfileSubscription(host_id=host.id, profile_id=profile.id),
        current_user=current_user,
    )


@router.delete(
    "/{profile_id}/hosts/{host_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_host_subscription(
    profile_id: int,
    host_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Response:
    # PRA-281: scope-gate the host id BEFORE the profile/subscription lookup, DB
    # delete, audit, or recompute (a hidden host id is not probeable).
    _scope_gate_system(db, current_user, host_id)
    profile = _live_or_404(db, profile_id, include_deleted=True)
    sub = (
        db.query(HostContentProfileSubscription)
        .filter(
            HostContentProfileSubscription.profile_id == profile.id,
            HostContentProfileSubscription.host_id == host_id,
        )
        .one_or_none()
    )
    if sub is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Host {host_id} is not directly subscribed to profile " f"{profile.id}"
            ),
        )
    db.delete(sub)
    db.commit()
    _emit(
        db,
        action="content_profile.subscription_removed",
        profile=profile,
        context={
            "scope_kind": "host",
            "scope_id": host_id,
            "actor_user_id": _actor_id(current_user),
        },
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{profile_id}/groups",
    response_model=SubscriptionRead,
    status_code=status.HTTP_201_CREATED,
)
async def add_group_subscription(
    profile_id: int,
    body: ProfileGroupSubscriptionAdd,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    # PRA-281: a group subscription binds a whole (possibly out-of-scope) group's
    # hosts to the profile and exposes the group label. Conservative default:
    # tenant-wide-admin-only for scoped callers, before the group lookup / insert /
    # audit / recompute (documented).
    _require_tenant_wide(
        db,
        current_user,
        "Group content-profile subscriptions require tenant-wide admin access",
    )
    profile = _live_or_404(db, profile_id)
    group = _group_or_400(db, body.group_id)
    return _add_subscription(
        db,
        profile=profile,
        scope_kind="group",
        scope_id=group.id,
        scope_label=group.name,
        row=GroupContentProfileSubscription(group_id=group.id, profile_id=profile.id),
        current_user=current_user,
    )


@router.delete(
    "/{profile_id}/groups/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_group_subscription(
    profile_id: int,
    group_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Response:
    _require_tenant_wide(
        db,
        current_user,
        "Group content-profile subscriptions require tenant-wide admin access",
    )
    profile = _live_or_404(db, profile_id, include_deleted=True)
    sub = (
        db.query(GroupContentProfileSubscription)
        .filter(
            GroupContentProfileSubscription.profile_id == profile.id,
            GroupContentProfileSubscription.group_id == group_id,
        )
        .one_or_none()
    )
    if sub is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(f"Group {group_id} is not subscribed to profile {profile.id}"),
        )
    db.delete(sub)
    db.commit()
    _emit(
        db,
        action="content_profile.subscription_removed",
        profile=profile,
        context={
            "scope_kind": "group",
            "scope_id": group_id,
            "actor_user_id": _actor_id(current_user),
        },
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{profile_id}/smart-groups",
    response_model=SubscriptionRead,
    status_code=status.HTTP_201_CREATED,
)
async def add_smart_group_subscription(
    profile_id: int,
    body: ProfileSmartGroupSubscriptionAdd,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    # PRA-281: a smart-group subscription binds the smart group's (materialized,
    # possibly out-of-scope) members and exposes the smart-group label.
    # Tenant-wide-admin-only for scoped callers (documented).
    _require_tenant_wide(
        db,
        current_user,
        "Smart-group content-profile subscriptions require tenant-wide admin access",
    )
    profile = _live_or_404(db, profile_id)
    sg = _smart_group_or_400(db, body.smart_group_id)
    return _add_subscription(
        db,
        profile=profile,
        scope_kind="smart_group",
        scope_id=sg.id,
        scope_label=sg.name,
        row=SmartGroupContentProfileSubscription(
            smart_group_id=sg.id, profile_id=profile.id
        ),
        current_user=current_user,
    )


@router.delete(
    "/{profile_id}/smart-groups/{smart_group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_smart_group_subscription(
    profile_id: int,
    smart_group_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Response:
    _require_tenant_wide(
        db,
        current_user,
        "Smart-group content-profile subscriptions require tenant-wide admin access",
    )
    profile = _live_or_404(db, profile_id, include_deleted=True)
    sub = (
        db.query(SmartGroupContentProfileSubscription)
        .filter(
            SmartGroupContentProfileSubscription.profile_id == profile.id,
            SmartGroupContentProfileSubscription.smart_group_id == smart_group_id,
        )
        .one_or_none()
    )
    if sub is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Smart group {smart_group_id} is not subscribed to "
                f"profile {profile.id}"
            ),
        )
    db.delete(sub)
    db.commit()
    _emit(
        db,
        action="content_profile.subscription_removed",
        profile=profile,
        context={
            "scope_kind": "smart_group",
            "scope_id": smart_group_id,
            "actor_user_id": _actor_id(current_user),
        },
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _add_subscription(
    db: Session,
    *,
    profile: ContentProfile,
    scope_kind: Literal["host", "group", "smart_group"],
    scope_id: int,
    scope_label: str,
    row,
    current_user,
) -> dict:
    db.add(row)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"{scope_kind} {scope_id} is already subscribed to profile "
                f"{profile.id}"
            ),
        ) from exc
    db.refresh(row)
    _emit(
        db,
        action="content_profile.subscription_added",
        profile=profile,
        context={
            "scope_kind": scope_kind,
            "scope_id": scope_id,
            "actor_user_id": _actor_id(current_user),
        },
    )
    return {
        "id": row.id,
        "profile_id": profile.id,
        "scope_kind": scope_kind,
        "scope_id": scope_id,
        "scope_label": scope_label,
        "created_at": row.created_at,
    }


# ---------------------------------------------------------------------------
# /{profile_id}/subscribers — flattened effective host list (slice #5)
# ---------------------------------------------------------------------------


@router.get(
    "/{profile_id}/subscribers",
    response_model=List[ProfileSubscriberRead],
)
async def list_profile_subscribers(
    profile_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Any:
    """List every host whose effective profile resolution lands on
    this profile (PRA-159 #5).

    Walks every System, runs
    ``ContentProfileService.resolve_content_for_host``, keeps hosts
    where ``state == "resolved"`` AND ``profile.profile_id ==
    profile_id``. Distinct from ``GET /subscriptions``: subscriptions
    list every binding row pointing AT the profile (some of which may
    not "win" precedence); subscribers is the *effective* set the
    apply orchestrator would write source config for.

    Tombstoned profile → empty list (resolver filters soft-deleted
    profiles from every tier).
    """
    profile = _live_or_404(db, profile_id, include_deleted=True)
    service = ContentProfileService(db)
    out: List[dict] = []
    # PRA-281: walk only the hosts visible to the caller, so a scoped caller never
    # sees a hidden host's hostname / via-binding via the effective set (empty
    # scope → empty). Admin (scope None) walks the whole fleet, unchanged.
    system_ids_with_hosts = scope_query_by_system(
        db.query(System.id, System.hostname), db, current_user, System.id
    ).all()
    for sid, hostname in system_ids_with_hosts:
        resolved = service.resolve_content_for_host(sid)
        if resolved.state != "resolved" or resolved.profile is None:
            continue
        if resolved.profile.profile_id != profile.id:
            continue
        out.append(
            {
                "host_id": sid,
                "hostname": hostname,
                "via_kind": resolved.profile.via_kind,
                "via_id": resolved.profile.via_id,
                "via_label": resolved.profile.via_label,
            }
        )
    out.sort(key=lambda r: r["hostname"])
    return out


# ---------------------------------------------------------------------------
# Resolved content / manifest / diff (slice #2) — declared BEFORE
# the bare /{profile_id} detail route per the route-ordering rule.
# ---------------------------------------------------------------------------


@router.get(
    "/{profile_id}/resolved",
    response_model=ResolvedContentRead,
)
async def get_profile_resolved(
    profile_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    """Flatten the profile into the canonical mirror-entry set
    (channel, mirror, suite, components, architectures, pin) that
    slice #3's apply orchestrator iterates.

    Always returns ``state='resolved'`` for a live profile (the
    profile itself is the binding subject — no tier resolution
    needed). Soft-deleted profile → 404.
    """
    profile = _live_or_404(db, profile_id)
    service = ContentProfileService(db)
    entries = service.resolve_mirror_entries_for_profile(profile.id)
    return {
        "state": "resolved",
        "profile": {
            "profile_id": profile.id,
            "profile_slug": profile.slug,
            "profile_display_name": profile.display_name,
            "via_kind": "direct",
            "via_id": None,
            "via_label": None,
        },
        "conflict_bindings": [],
        "entries": [_resolved_entry_to_dict(e) for e in entries],
    }


@router.get(
    "/{profile_id}/manifest",
    response_model=ProfileManifestRead,
)
async def get_profile_manifest(
    profile_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    """Flat package index across the profile's resolved mirror
    entries. Used by inspection UIs and as the input the diff
    endpoint runs against.

    Missing manifest files (mirror not yet synced) drop out with a
    log warning; their entries contribute zero packages but the
    response still returns 200 with the available union.
    """
    profile = _live_or_404(db, profile_id)
    return compute_profile_manifest(db, profile.id)


@router.get(
    "/{profile_id}/diff",
    response_model=ProfileDiffRead,
)
async def get_profile_diff(
    profile_id: int,
    from_profile_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    """Diff packages between two profiles.

    ``from_profile_id`` is the source state; the path's
    ``profile_id`` is the target. Result rows show ``from_version``
    / ``to_version`` per ``(package, arch)``. Same-profile requests
    (``from_profile_id == profile_id``) are rejected with 400 — the
    public contract locked in slice #2-a; the underlying service is
    permissive but the route is the user-facing surface.

    Both profiles must exist (live; tombstones can be diffed via the
    explicit include_deleted=true detail flag in v2 if operators
    ask for it).
    """
    if from_profile_id == profile_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="from_profile_id must differ from the path profile id",
        )
    target = _live_or_404(db, profile_id)
    source = _live_or_404(db, from_profile_id)
    return compute_profile_diff(db, from_profile_id=source.id, to_profile_id=target.id)


# ---------------------------------------------------------------------------
# /{profile_id} — detail / patch / delete
# ---------------------------------------------------------------------------


@router.get("/{profile_id}", response_model=ContentProfileRead)
async def get_profile(
    profile_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
    include_deleted: bool = False,
) -> Any:
    """Detail read mirrors the list semantics: default live-only,
    pass ``?include_deleted=true`` for tombstones.
    """
    return _profile_to_read(
        _live_or_404(db, profile_id, include_deleted=include_deleted), db
    )


@router.patch("/{profile_id}", response_model=ContentProfileRead)
async def update_profile(
    profile_id: int,
    body: ContentProfileUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    _require_tenant_wide(
        db, current_user, "Managing content profiles requires tenant-wide admin access"
    )
    profile = _live_or_404(db, profile_id)
    update_fields = body.dict(exclude_unset=True)
    if not update_fields:
        return _profile_to_read(profile, db)

    for field, value in update_fields.items():
        setattr(profile, field, value)
    db.commit()
    db.refresh(profile)

    _emit(
        db,
        action="content_profile.updated",
        profile=profile,
        context={
            "fields": sorted(update_fields.keys()),
            "actor_user_id": _actor_id(current_user),
        },
    )
    return _profile_to_read(profile, db)


@router.delete("/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_profile(
    profile_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Response:
    """Soft-delete the profile.

    Subscriptions are NOT cascade-cleaned — the operator may un-delete
    the profile and the subscriptions should still resolve. The
    resolver filters soft-deleted profiles out at every tier, so a
    soft-deleted profile is dormant from an effective-resolution
    perspective.
    """
    _require_tenant_wide(
        db, current_user, "Managing content profiles requires tenant-wide admin access"
    )
    profile = _live_or_404(db, profile_id)
    profile.deleted_at = datetime.utcnow()
    db.commit()
    _emit(
        db,
        action="content_profile.deleted",
        profile=profile,
        context={"actor_user_id": _actor_id(current_user)},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Mounted under /systems by main.py — host effective-profile read.
# /resolved declared BEFORE the bare /content-profile to keep the
# longest-prefix match deterministic.
# ---------------------------------------------------------------------------


@systems_router.get(
    "/{system_id}/content-profile/resolved",
    response_model=ResolvedContentRead,
)
async def get_host_resolved_content(
    system_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    """Resolve the host's effective profile AND the flattened
    mirror-entry set the host would receive.

    Used by the host detail Profile tab so operators can preview
    the source-list output slice #3 will produce. ``state`` mirrors
    ``GET /content-profile``: when state is ``no_profile`` or
    ``conflict`` the entries list is empty (apply orchestrator will
    refuse).
    """
    # PRA-281: non-disclosing 404 before the System lookup, ContentProfileService
    # resolution, conflict-binding / mirror-entry / profile-label serialization.
    _scope_gate_system(db, current_user, system_id)
    if db.query(System).filter(System.id == system_id).first() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System {system_id} not found",
        )
    service = ContentProfileService(db)
    resolved = service.resolve_content_for_host(system_id)
    return {
        "state": resolved.state,
        "profile": _binding_to_read(resolved.profile)
        if resolved.profile is not None
        else None,
        "conflict_bindings": [_binding_to_read(b) for b in resolved.conflict_bindings],
        "entries": [_resolved_entry_to_dict(e) for e in resolved.entries],
    }


@systems_router.get(
    "/{system_id}/content-profile",
    response_model=EffectiveProfileRead,
)
async def get_host_effective_profile(
    system_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    """Resolve the effective profile for a host.

    Returns ``state`` ∈ ``no_profile | resolved | conflict``. UI uses
    this to surface ambiguity before an operator clicks Apply
    (slice #3 will refuse on ``conflict``).
    """
    # PRA-281: non-disclosing 404 before the System lookup / resolver.
    _scope_gate_system(db, current_user, system_id)
    if db.query(System).filter(System.id == system_id).first() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System {system_id} not found",
        )
    service = ContentProfileService(db)
    return _effective_to_read(service.resolve_effective(system_id))
