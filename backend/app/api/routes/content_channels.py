"""Content channel CRUD + repo sub-resource (PRA-159 slice #1).

Mounts at ``/content-channels``. Channels are pure content
composition — see ``ContentChannel`` and ``ContentChannelRepo`` ORM
docstrings for the locked semantics. Hosts subscribe to
``ContentProfile`` rows that compose channels; this router does NOT
expose host-binding endpoints.

Route ordering note (``feedback_fastapi_route_ordering.md``): the
``{channel_id}/repos`` sub-resource is declared before the bare
``/{channel_id}`` detail route so the wildcard match doesn't swallow
it.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.schemas.content_channels import (
    ContentChannelCreate,
    ContentChannelRead,
    ContentChannelRepoAdd,
    ContentChannelRepoPinUpdate,
    ContentChannelRepoRead,
    ContentChannelUpdate,
)
from app.core.auth import get_current_user, require_role
from app.db.models import (
    ContentChannel,
    ContentChannelRepo,
    ContentProfileChannel,
    MirrorRepo,
)
from app.db.session import get_db
from app.services import audit_event_service
from app.services.content_profile_service import (
    ContentProfileError,
    ContentProfileService,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["content-channels"])


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _repo_to_read(repo: ContentChannelRepo) -> dict:
    mirror = repo.mirror
    pinned_sha = repo.pinned_run.manifest_sha256 if repo.pinned_run else None
    effective_suite = repo.suite_override or (
        mirror.distribution if mirror is not None else ""
    )
    return {
        "id": repo.id,
        "channel_id": repo.channel_id,
        "mirror_id": repo.mirror_id,
        "mirror_slug": mirror.slug if mirror is not None else "",
        "suite_override": repo.suite_override,
        "effective_suite": effective_suite,
        "pinned_run_id": repo.pinned_run_id,
        "pinned_manifest_sha256": pinned_sha,
        "created_at": repo.created_at,
        "updated_at": repo.updated_at,
    }


def _channel_to_read(channel: ContentChannel) -> dict:
    return {
        "id": channel.id,
        "slug": channel.slug,
        "display_name": channel.display_name,
        "package_family": channel.package_family,
        "description": channel.description,
        "deleted_at": channel.deleted_at,
        "created_at": channel.created_at,
        "updated_at": channel.updated_at,
        "repos": [_repo_to_read(r) for r in channel.repos],
    }


def _live_or_404(
    db: Session, channel_id: int, *, include_deleted: bool = False
) -> ContentChannel:
    q = db.query(ContentChannel).filter(ContentChannel.id == channel_id)
    if not include_deleted:
        q = q.filter(ContentChannel.deleted_at.is_(None))
    channel = q.one_or_none()
    if channel is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Content channel {channel_id} not found",
        )
    return channel


def _live_mirror_or_400(db: Session, mirror_id: int) -> MirrorRepo:
    mirror = (
        db.query(MirrorRepo)
        .filter(MirrorRepo.id == mirror_id, MirrorRepo.deleted_at.is_(None))
        .one_or_none()
    )
    if mirror is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Mirror {mirror_id} not found or soft-deleted",
        )
    return mirror


def _actor_id(current_user) -> Optional[int]:
    return getattr(current_user, "id", None) if current_user is not None else None


def _emit(db: Session, *, action: str, channel: ContentChannel, context: dict) -> None:
    """Emit an audit event for a channel mutation.

    Uses the shared ``audit_event_service.emit`` (commits on the same
    session as the mutation). Mutation routes commit BEFORE calling
    here is unnecessary — emit's own commit covers both since
    SQLAlchemy session unit-of-work batches them; the route calls
    ``db.commit()`` after the mutation and BEFORE this helper, then
    emit issues a small follow-on commit. Keeps the audit row
    consistent with the change it describes.
    """
    audit_event_service.emit(
        db,
        action=action,
        target_kind="content_channel",
        target_id=str(channel.id),
        context={"channel_slug": channel.slug, **context},
    )
    # PRA-159 #4: channel CRUD + repo-pin changes affect the
    # profile.pinned predicate (a profile composing this channel
    # may have just gained / lost a pinned repo). Fleet-wide
    # recompute on profile.*-referencing smart groups; no-op when
    # no such groups exist.
    from app.services.smart_group_service import recompute_profile_groups

    recompute_profile_groups(db)


# ---------------------------------------------------------------------------
# CRUD — list / create at the collection root
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=ContentChannelRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_channel(
    body: ContentChannelCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    if (
        db.query(ContentChannel).filter(ContentChannel.slug == body.slug).first()
    ) is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Content channel with slug '{body.slug}' already exists",
        )

    channel = ContentChannel(
        slug=body.slug,
        display_name=body.display_name,
        package_family=body.package_family,
        description=body.description,
    )
    db.add(channel)
    db.commit()
    db.refresh(channel)

    _emit(
        db,
        action="content_channel.created",
        channel=channel,
        context={
            "package_family": channel.package_family,
            "display_name": channel.display_name,
            "actor_user_id": _actor_id(current_user),
        },
    )
    logger.info("Created content channel %s (id=%d)", channel.slug, channel.id)
    return _channel_to_read(channel)


@router.get("", response_model=List[ContentChannelRead])
async def list_channels(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
    include_deleted: bool = False,
) -> Any:
    q = db.query(ContentChannel)
    if not include_deleted:
        q = q.filter(ContentChannel.deleted_at.is_(None))
    channels = q.order_by(ContentChannel.slug).all()
    return [_channel_to_read(c) for c in channels]


# ---------------------------------------------------------------------------
# Sub-resources — declared BEFORE /{channel_id} (route-ordering rule)
# ---------------------------------------------------------------------------


@router.post(
    "/{channel_id}/repos",
    response_model=ContentChannelRepoRead,
    status_code=status.HTTP_201_CREATED,
)
async def add_channel_repo(
    channel_id: int,
    body: ContentChannelRepoAdd,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    channel = _live_or_404(db, channel_id)
    mirror = _live_mirror_or_400(db, body.mirror_id)

    service = ContentProfileService(db)
    try:
        service.assert_channel_repo_family_match(
            channel.package_family, mirror.package_family
        )
    except ContentProfileError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    if body.pinned_run_id is not None:
        try:
            service.assert_pinned_run_belongs_to_mirror(body.pinned_run_id, mirror.id)
        except ContentProfileError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            )

    repo = ContentChannelRepo(
        channel_id=channel.id,
        mirror_id=mirror.id,
        suite_override=body.suite_override,
        pinned_run_id=body.pinned_run_id,
    )
    db.add(repo)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Mirror {mirror.id} is already linked to channel "
                f"{channel.id}"
                + (
                    f" with suite_override={body.suite_override!r}"
                    if body.suite_override is not None
                    else " (inherit-suite entry already exists)"
                )
            ),
        ) from exc
    db.refresh(repo)

    _emit(
        db,
        action="content_channel.repo_added",
        channel=channel,
        context={
            "mirror_id": mirror.id,
            "mirror_slug": mirror.slug,
            "suite_override": body.suite_override,
            "pinned_run_id": body.pinned_run_id,
            "actor_user_id": _actor_id(current_user),
        },
    )
    return _repo_to_read(repo)


@router.patch(
    "/{channel_id}/repos/{repo_id}/pin",
    response_model=ContentChannelRepoRead,
)
async def update_channel_repo_pin(
    channel_id: int,
    repo_id: int,
    body: ContentChannelRepoPinUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    channel = _live_or_404(db, channel_id)
    repo = (
        db.query(ContentChannelRepo)
        .filter(
            ContentChannelRepo.id == repo_id,
            ContentChannelRepo.channel_id == channel.id,
        )
        .one_or_none()
    )
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Channel repo {repo_id} not found in channel {channel.id}",
        )

    if body.pinned_run_id is not None:
        service = ContentProfileService(db)
        try:
            service.assert_pinned_run_belongs_to_mirror(
                body.pinned_run_id, repo.mirror_id
            )
        except ContentProfileError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            )

    previous = repo.pinned_run_id
    repo.pinned_run_id = body.pinned_run_id
    db.commit()
    db.refresh(repo)

    _emit(
        db,
        action="content_channel.repo_pin_updated",
        channel=channel,
        context={
            "repo_id": repo.id,
            "mirror_id": repo.mirror_id,
            "previous_pinned_run_id": previous,
            "pinned_run_id": repo.pinned_run_id,
            "actor_user_id": _actor_id(current_user),
        },
    )
    return _repo_to_read(repo)


@router.delete(
    "/{channel_id}/repos/{repo_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_channel_repo(
    channel_id: int,
    repo_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Response:
    channel = _live_or_404(db, channel_id)
    repo = (
        db.query(ContentChannelRepo)
        .filter(
            ContentChannelRepo.id == repo_id,
            ContentChannelRepo.channel_id == channel.id,
        )
        .one_or_none()
    )
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Channel repo {repo_id} not found in channel {channel.id}",
        )

    mirror_id = repo.mirror_id
    suite_override = repo.suite_override
    db.delete(repo)
    db.commit()

    _emit(
        db,
        action="content_channel.repo_removed",
        channel=channel,
        context={
            "repo_id": repo_id,
            "mirror_id": mirror_id,
            "suite_override": suite_override,
            "actor_user_id": _actor_id(current_user),
        },
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# /{channel_id} — detail / patch / delete
# ---------------------------------------------------------------------------


@router.get("/{channel_id}", response_model=ContentChannelRead)
async def get_channel(
    channel_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
    include_deleted: bool = False,
) -> Any:
    """Detail read mirrors the list semantics: default live-only,
    pass ``?include_deleted=true`` to read tombstones. Keeps API surface symmetric so UI doesn't need to know
    which routes silently surface deleted rows.
    """
    return _channel_to_read(
        _live_or_404(db, channel_id, include_deleted=include_deleted)
    )


@router.patch("/{channel_id}", response_model=ContentChannelRead)
async def update_channel(
    channel_id: int,
    body: ContentChannelUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    channel = _live_or_404(db, channel_id)
    update_fields = body.dict(exclude_unset=True)
    if not update_fields:
        return _channel_to_read(channel)

    for field, value in update_fields.items():
        setattr(channel, field, value)
    db.commit()
    db.refresh(channel)

    _emit(
        db,
        action="content_channel.updated",
        channel=channel,
        context={
            "fields": sorted(update_fields.keys()),
            "actor_user_id": _actor_id(current_user),
        },
    )
    return _channel_to_read(channel)


@router.delete("/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_channel(
    channel_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Response:
    """Soft-delete the channel (``deleted_at = now``).

    Refuses if ANY ``ContentProfileChannel`` row references this
    channel — including links from soft-deleted profiles. "Referenced
    anywhere, dead or alive" is the safer v1 rule: it avoids confusing un-delete races where reviving a
    profile would silently re-enliven a link to a channel the
    operator just retired. The link is the relationship; if the
    profile comes back, the channel must too. This isn't a hard FK
    constraint because soft-delete shouldn't cascade through joins
    on ``deleted_at`` semantics.
    """
    channel = _live_or_404(db, channel_id)

    in_use_count = (
        db.query(ContentProfileChannel)
        .filter(ContentProfileChannel.channel_id == channel.id)
        .count()
    )
    if in_use_count > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Channel {channel.slug!r} is composed by {in_use_count} "
                "profile(s); remove the profile-channel links first"
            ),
        )

    channel.deleted_at = datetime.utcnow()
    db.commit()

    _emit(
        db,
        action="content_channel.deleted",
        channel=channel,
        context={"actor_user_id": _actor_id(current_user)},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
