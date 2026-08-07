"""
API routes for tag management.
Includes endpoints for CRUD operations on tags and system-tag assignments.
"""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role
from ...db.models import System, Tag, User, system_tag
from ...db.session import get_db
from ...services.access_authorization_service import (
    scoped_system_ids,
    user_can_access_system,
)

router = APIRouter(redirect_slashes=False)


def _enforce_batch_scope(db: Session, current_user: User, system_ids) -> None:
    """PRA-281: reject the whole tag assignment/removal request with a
    non-disclosing 404 if any requested system is out of scope — never partially
    assign/unassign a mixed batch, before any DB mutation or audit."""
    scope = scoped_system_ids(db, current_user)
    if scope is None:
        return
    for sid in system_ids:
        if not user_can_access_system(db, current_user, sid):
            raise HTTPException(status_code=404, detail="System not found")


class TagCreate(BaseModel):
    """Request body for creating a tag."""

    name: str = Field(..., description="Tag name")
    color: str = Field("#6B7280", description="Tag color hex code")


class TagUpdate(BaseModel):
    """Request body for updating a tag."""

    name: Optional[str] = Field(None, description="Tag name")
    color: Optional[str] = Field(None, description="Tag color hex code")


class TagResponse(BaseModel):
    """Response model for tag data."""

    id: int
    name: str
    color: str
    created_by: int
    system_count: int = 0
    created_at: datetime
    updated_at: datetime

    class Config:  # pylint: disable=too-few-public-methods, missing-class-docstring
        orm_mode = True


class SystemIds(BaseModel):
    """Request body for assigning/removing systems."""

    system_ids: List[int] = Field(..., description="List of system IDs")


class BulkAssign(BaseModel):
    """Request body for bulk tag-system assignment."""

    tag_ids: List[int] = Field(..., description="List of tag IDs")
    system_ids: List[int] = Field(..., description="List of system IDs")


def _tag_to_response(tag: Tag, db: Session, scope=None) -> dict:
    """Convert a Tag model to a response dictionary.

    PRA-281: tag definitions (name/color) are global taxonomy, but ``system_count``
    is host-derived. For a scoped caller (``scope`` is a set) the count includes
    only in-scope systems, so a tag never reveals how many out-of-scope systems
    carry it. Admin (``scope`` None) sees the full count.
    """
    count_q = (
        db.query(func.count())  # pylint: disable=not-callable
        .select_from(system_tag)
        .filter(system_tag.c.tag_id == tag.id)
    )
    if scope is not None:
        if not scope:
            count_q = count_q.filter(False)
        else:
            count_q = count_q.filter(system_tag.c.system_id.in_(scope))
    system_count = count_q.scalar()
    return {
        "id": tag.id,
        "name": tag.name,
        "color": tag.color,
        "created_by": tag.created_by,
        "system_count": system_count,
        "created_at": tag.created_at,
        "updated_at": tag.updated_at,
    }


@router.get("", response_model=List[TagResponse])
async def list_tags(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all tags."""
    tags = db.query(Tag).order_by(Tag.name).all()
    scope = scoped_system_ids(db, current_user)
    return [_tag_to_response(t, db, scope=scope) for t in tags]


@router.post("", response_model=TagResponse, status_code=status.HTTP_201_CREATED)
async def create_tag(
    body: TagCreate,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Create a new tag."""
    # Validate unique name
    existing = db.query(Tag).filter(Tag.name == body.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A tag with name '{body.name}' already exists",
        )

    # Validate color format
    if body.color and (
        len(body.color) != 7
        or not body.color.startswith("#")
        or not all(c in "0123456789abcdefABCDEF" for c in body.color[1:])
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Color must be a valid hex color code (e.g. #6B7280)",
        )

    try:
        tag = Tag(
            name=body.name,
            color=body.color,
            created_by=current_user.id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(tag)
        db.commit()
        db.refresh(tag)
        return _tag_to_response(tag, db)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A tag with this name already exists",
        ) from e


@router.get("/{tag_id}", response_model=TagResponse)
async def get_tag(
    tag_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get a single tag with system count."""
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tag with ID {tag_id} not found",
        )
    return _tag_to_response(tag, db, scope=scoped_system_ids(db, current_user))


@router.put("/{tag_id}", response_model=TagResponse)
async def update_tag(
    tag_id: int,
    body: TagUpdate,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Update a tag's name and/or color."""
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tag with ID {tag_id} not found",
        )

    if body.name is not None:
        # Check for duplicate name
        existing = db.query(Tag).filter(Tag.name == body.name, Tag.id != tag_id).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Another tag with name '{body.name}' already exists",
            )
        tag.name = body.name

    if body.color is not None:
        if (
            len(body.color) != 7
            or not body.color.startswith("#")
            or not all(c in "0123456789abcdefABCDEF" for c in body.color[1:])
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Color must be a valid hex color code (e.g. #6B7280)",
            )
        tag.color = body.color

    tag.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(tag)
    return _tag_to_response(tag, db)


@router.delete("/{tag_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tag(
    tag_id: int,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Delete a tag. System associations are removed via CASCADE."""
    # PRA-281: deleting a tag CASCADE-removes its system associations, including
    # links to out-of-scope systems (mutating hidden hosts' tag membership). Unlike
    # create/update — which touch only the global name/color taxonomy — delete is a
    # system-association mutation, so it is tenant-wide-admin-only for scoped
    # callers. Fail closed BEFORE the tag lookup or any cascade, non-disclosingly.
    if scoped_system_ids(db, current_user) is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Deleting tags requires tenant-wide admin access",
        )

    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tag with ID {tag_id} not found",
        )

    db.delete(tag)
    db.commit()
    return None


@router.post("/{tag_id}/systems", status_code=status.HTTP_200_OK)
async def assign_tag_to_systems(
    tag_id: int,
    body: SystemIds,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Assign a tag to one or more systems."""
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tag with ID {tag_id} not found",
        )

    _enforce_batch_scope(db, current_user, body.system_ids)

    # Validate all systems exist
    systems = db.query(System).filter(System.id.in_(body.system_ids)).all()
    found_ids = {s.id for s in systems}
    missing = set(body.system_ids) - found_ids
    if missing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Systems not found: {sorted(missing)}",
        )

    # Add associations (skip duplicates)
    added = 0
    for system in systems:
        if tag not in system.tags:
            system.tags.append(tag)
            added += 1

    db.commit()
    return {
        "message": f"Tag '{tag.name}' assigned to {added} systems",
    }


@router.delete("/{tag_id}/systems", status_code=status.HTTP_200_OK)
async def remove_tag_from_systems(
    tag_id: int,
    body: SystemIds,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Remove a tag from one or more systems."""
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tag with ID {tag_id} not found",
        )

    _enforce_batch_scope(db, current_user, body.system_ids)

    systems = db.query(System).filter(System.id.in_(body.system_ids)).all()

    removed = 0
    for system in systems:
        if tag in system.tags:
            system.tags.remove(tag)
            removed += 1

    db.commit()
    return {
        "message": f"Tag '{tag.name}' removed from {removed} systems",
    }


@router.post("/bulk-assign", status_code=status.HTTP_200_OK)
async def bulk_assign_tags(
    body: BulkAssign,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Bulk assign multiple tags to multiple systems."""
    # PRA-281: reject the whole batch if any target system is out of scope.
    _enforce_batch_scope(db, current_user, body.system_ids)

    # Validate tags exist
    tags = db.query(Tag).filter(Tag.id.in_(body.tag_ids)).all()
    found_tag_ids = {t.id for t in tags}
    missing_tags = set(body.tag_ids) - found_tag_ids
    if missing_tags:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tags not found: {sorted(missing_tags)}",
        )

    # Validate systems exist
    systems = db.query(System).filter(System.id.in_(body.system_ids)).all()
    found_sys_ids = {s.id for s in systems}
    missing_systems = set(body.system_ids) - found_sys_ids
    if missing_systems:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Systems not found: {sorted(missing_systems)}",
        )

    added = 0
    for system in systems:
        for tag in tags:
            if tag not in system.tags:
                system.tags.append(tag)
                added += 1

    db.commit()
    return {
        "message": (
            f"Assigned {len(tags)} tags to {len(systems)} systems "
            f"({added} new associations)"
        ),
    }
