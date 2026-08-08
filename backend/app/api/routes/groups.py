"""
API routes for system group management.
Includes endpoints for CRUD operations on groups and system assignments.
"""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role
from ...db.models import Group, System, User
from ...db.session import get_db
from ...services.access_authorization_service import (
    scoped_system_ids,
    user_can_access_system,
)
from ...services.system_audit_service import record_audit

router = APIRouter()


def _group_member_ids(db: Session, group_id: int) -> set:
    """The set of system ids directly assigned to a group."""
    return {
        row[0] for row in db.query(System.id).filter(System.group_id == group_id).all()
    }


def _group_visible_to_scope(db: Session, group_id: int, scope) -> bool:
    """PRA-281: a group's member list is host-derived. Admin (scope ``None``) sees
    all. A scoped caller may see a group only when its direct member systems are
    non-empty AND entirely in scope — empty, mixed, and out-of-scope groups are
    hidden (fail closed), so no out-of-scope hostname/id/count/membership leaks."""
    if scope is None:
        return True
    members = _group_member_ids(db, group_id)
    return bool(members) and members.issubset(scope)


class GroupBase(BaseModel):
    """Base model for group data."""

    name: str = Field(..., description="Group name")
    description: Optional[str] = Field(None, description="Group description")
    parent_id: Optional[int] = Field(None, description="Parent group ID")


class GroupCreate(GroupBase):
    """Model for creating a new group."""


class GroupUpdate(GroupBase):
    """Model for updating an existing group."""


class GroupResponse(GroupBase):
    """
    Response model for group data.

    Extends GroupBase and adds ID and timestamp fields.
    """

    id: int
    created_at: datetime
    updated_at: datetime
    """Timestamp of when the group was created"""

    class Config:  # pylint: disable=too-few-public-methods, missing-class-docstring
        orm_mode = True


class GroupDetailResponse(GroupResponse):
    """
    Detailed response model for group data including parent and children.

    Extends GroupResponse and adds parent, children, and system count fields.
    """

    parent: Optional[GroupResponse] = None
    children: List[GroupResponse] = []
    system_count: int = 0

    class Config:  # pylint: disable=too-few-public-methods, missing-class-docstring
        orm_mode = True


@router.post("", response_model=GroupResponse, status_code=status.HTTP_201_CREATED)
async def create_group(
    group: GroupCreate,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Create a new system group.

    This endpoint creates a new group for organizing systems with validation for:
    - Required fields
    - Duplicate detection
    - Reference integrity for parent group
    """
    # Validate parent group if provided
    if group.parent_id:
        parent_group = db.query(Group).filter(Group.id == group.parent_id).first()
        if not parent_group:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Parent group with ID {group.parent_id} not found",
            )

    # Check for duplicate group name
    existing_group = db.query(Group).filter(Group.name == group.name).first()
    if existing_group:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A group with name '{group.name}' already exists",
        )

    try:
        # Create new group
        db_group = Group(
            name=group.name,
            description=group.description,
            parent_id=group.parent_id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )

        db.add(db_group)
        db.commit()
        db.refresh(db_group)

        return db_group
    except IntegrityError as e:
        db.rollback()
        if "unique constraint" in str(e.orig).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A group with this name already exists",
            ) from e
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid data: {str(e)}",
        ) from e
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while creating the group: {str(e)}",
        ) from e


@router.get("", response_model=List[GroupResponse])
async def get_all_groups(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get all system groups.

    Returns a list of all groups with their basic information.
    """
    groups = db.query(Group).all()
    # PRA-281: a scoped caller only sees groups whose direct members are entirely
    # in scope (admin sees all). Group create/update remain global taxonomy
    # (no host-derived payload); reads are host-derived so they are scoped.
    scope = scoped_system_ids(db, current_user)
    if scope is not None:
        groups = [g for g in groups if _group_visible_to_scope(db, g.id, scope)]
    return groups


@router.get("/{group_id}", response_model=GroupDetailResponse)
async def get_group_details(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get detailed information about a specific group.

    Returns comprehensive information about the specified group, including
    parent group, child groups, and system count.
    """
    # Get the group
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group with ID {group_id} not found",
        )
    # PRA-281: non-disclosing 404 for a group not fully in scope, before any
    # member/child hostname or count is resolved.
    scope = scoped_system_ids(db, current_user)
    if scope is not None and not _group_visible_to_scope(db, group_id, scope):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group with ID {group_id} not found",
        )

    # Get the parent group if it exists (only if visible in scope)
    parent = None
    if group.parent_id:
        if scope is None or _group_visible_to_scope(db, group.parent_id, scope):
            parent = db.query(Group).filter(Group.id == group.parent_id).first()

    # Get child groups (scoped callers only see children visible to them)
    children = db.query(Group).filter(Group.parent_id == group_id).all()
    if scope is not None:
        children = [c for c in children if _group_visible_to_scope(db, c.id, scope)]

    # Count systems in this group
    system_count = (
        db.query(func.count())  # pylint: disable=not-callable
        .select_from(System)
        .filter(System.group_id == group_id)
        .scalar()
    )

    # Build response
    result = {
        "id": group.id,
        "name": group.name,
        "description": group.description,
        "parent_id": group.parent_id,
        "created_at": group.created_at,
        "updated_at": group.updated_at,
        "parent": parent,
        "children": children,
        "system_count": system_count,
    }

    return result


@router.put("/{group_id}", response_model=GroupResponse)
async def update_group(
    group_id: int,
    group: GroupUpdate,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Update an existing group.

    This endpoint updates a group's information with validation for:
    - Required fields
    - Duplicate detection
    - Reference integrity for parent group
    - Circular reference prevention
    """
    # Get the group to update
    db_group = db.query(Group).filter(Group.id == group_id).first()
    if not db_group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group with ID {group_id} not found",
        )

    # Validate parent group if provided
    if group.parent_id:
        # Prevent circular references
        if group.parent_id == group_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A group cannot be its own parent",
            )

        # Check if parent exists
        parent_group = db.query(Group).filter(Group.id == group.parent_id).first()
        if not parent_group:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Parent group with ID {group.parent_id} not found",
            )

        # Check for circular references in the hierarchy
        current_parent_id = group.parent_id
        visited = set([group_id])
        while current_parent_id:
            if current_parent_id in visited:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Circular reference detected in group hierarchy",
                )
            visited.add(current_parent_id)
            parent = db.query(Group).filter(Group.id == current_parent_id).first()
            if not parent:
                break
            current_parent_id = parent.parent_id

    # Check for duplicate group name
    existing_group = (
        db.query(Group).filter(Group.name == group.name, Group.id != group_id).first()
    )
    if existing_group:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Another group with name '{group.name}' already exists",
        )

    try:
        # Update group fields
        db_group.name = group.name
        db_group.description = group.description
        db_group.parent_id = group.parent_id
        db_group.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(db_group)

        return db_group
    except IntegrityError as e:
        db.rollback()
        if "unique constraint" in str(e.orig).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Another group with this name already exists",
            ) from e
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid data: {str(e)}",
        ) from e
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while updating the group: {str(e)}",
        ) from e


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_id: int,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Delete a group.

    This endpoint deletes a group if it has no systems assigned to it.
    """
    # PRA-281: deleting a group surfaces a host-derived "N systems assigned" count
    # whose safety guard needs the FULL (fleet-wide) count, so a scoped caller
    # cannot delete without leaking it — restrict delete to tenant-wide admins.
    if scoped_system_ids(db, current_user) is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Deleting groups requires tenant-wide admin access",
        )

    # Get the group to delete
    db_group = db.query(Group).filter(Group.id == group_id).first()
    if not db_group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group with ID {group_id} not found",
        )

    # Check if group has systems
    system_count = (
        db.query(func.count())  # pylint: disable=not-callable
        .select_from(System)
        .filter(System.group_id == group_id)
        .scalar()
    )
    if system_count > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot delete group with {system_count} systems assigned. Reassign systems first.",  # pylint: disable=line-too-long
        )

    # Check if group has child groups
    child_count = (
        db.query(func.count())  # pylint: disable=not-callable
        .select_from(Group)
        .filter(Group.parent_id == group_id)
        .scalar()
    )
    if child_count > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot delete group with {child_count} child groups. Remove child groups first.",  # pylint: disable=line-too-long
        )

    try:
        # Delete the group
        db.delete(db_group)
        db.commit()

        return None
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while deleting the group: {str(e)}",
        ) from e


class SystemAssignment(BaseModel):
    """Model for assigning systems to a group."""

    system_ids: List[int] = Field(
        ..., description="List of system IDs to assign to the group"
    )


@router.post("/{group_id}/systems", status_code=status.HTTP_200_OK)
async def assign_systems_to_group(
    group_id: int,
    assignment: SystemAssignment,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Assign systems to a group.

    This endpoint assigns multiple systems to a group in a single operation.
    """
    # Get the group
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group with ID {group_id} not found",
        )

    # PRA-281: reject the whole request with a non-disclosing 404 if any requested
    # system is out of scope — never partially assign a mixed batch, before any
    # System mutation or audit.
    scope = scoped_system_ids(db, current_user)
    if scope is not None:
        for system_id in assignment.system_ids:
            if not user_can_access_system(db, current_user, system_id):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="System not found",
                )

    # Validate all systems exist
    for system_id in assignment.system_ids:
        system = db.query(System).filter(System.id == system_id).first()
        if not system:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"System with ID {system_id} not found",
            )

    try:
        # Update all systems to the new group
        updated_count = 0
        for system_id in assignment.system_ids:
            system = db.query(System).filter(System.id == system_id).first()
            if system:
                old_group_id = system.group_id
                system.group_id = group_id
                system.updated_at = datetime.utcnow()
                if old_group_id != group_id:
                    record_audit(
                        db,
                        system_id=system.id,
                        user_id=current_user.id,
                        operation="group_change",
                        audit_type="group_id",
                        old_value=old_group_id,
                        new_value=group_id,
                    )
                updated_count += 1

        db.commit()

        return {
            "message": f"Successfully assigned {updated_count} systems to group '{group.name}'"
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while assigning systems to the group: {str(e)}",
        ) from e


@router.get("/{group_id}/systems", response_model=List[dict])
async def get_systems_in_group(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get all systems in a group.

    Returns a list of all systems assigned to the specified group.
    """
    # Get the group
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group with ID {group_id} not found",
        )
    # PRA-281: non-disclosing 404 for a group not fully in scope, before any
    # member hostname is returned.
    scope = scoped_system_ids(db, current_user)
    if scope is not None and not _group_visible_to_scope(db, group_id, scope):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group with ID {group_id} not found",
        )

    # Query systems in this group
    systems = db.query(System).filter(System.group_id == group_id).all()

    # Convert to list of dictionaries
    result = []
    for system in systems:
        result.append(
            {
                "id": system.id,
                "hostname": system.hostname,
                "ip_address": str(system.ip_address),
                "status": system.status,
                "os_version": system.os_version,
                "registered_at": system.registered_at,
            }
        )

    return result
