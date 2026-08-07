"""
Linux system management routes module.

This module provides API endpoints for managing Linux systems in the inventory,
including registration, updates, deletion, and querying system information.
"""

import ipaddress  # pylint: disable=unused-import
import re
from datetime import datetime
from typing import Any, Dict, List, Optional  # pylint: disable=unused-import

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, IPvAnyAddress, validator
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role, require_system_access
from ...db.models import (
    Credential,
    Distro,
    Group,
    System,
    SystemMetadata,
    Tag,
    User,
    system_tag,
)
from ...db.session import get_db
from ...db.ssh_security_models import SSHSecurityPolicy
from ...services import license_service
from ...services.access_authorization_service import scope_query_by_system
from ...services.notification_service import create_notification
from ...services.system_audit_service import record_audit, snapshot_system

router = APIRouter()


class SystemCreate(BaseModel):
    """
    Schema for creating a new system in the inventory.

    Includes validation for hostname format, status values, and environment types.
    """

    hostname: str = Field(..., description="System hostname")
    ip_address: IPvAnyAddress = Field(..., description="System IP address")
    distro_id: int = Field(..., description="Linux distribution ID")
    os_version: Optional[str] = Field(
        None,
        description="Operating system version (optional, will use version from distribution)",
    )
    status: str = Field(
        ..., description="System status (Active, Inactive, Maintenance)"
    )
    group_id: int = Field(..., description="System group ID")
    credentials_id: int = Field(..., description="Credentials ID for system access")
    update_policy: Optional[str] = Field(None, description="System update policy")
    description: Optional[str] = Field(None, description="System description")
    environment: Optional[str] = Field(
        None, description="Environment (Production, Staging, Development)"
    )  # pylint: disable=line-too-long
    tags: Optional[List[str]] = Field(None, description="System tags or labels")

    @validator("hostname")
    def validate_hostname(cls, v):  # pylint: disable=no-self-argument
        """
        Validate hostname format according to RFC 1123 standards.

        Ensures the hostname is not empty and follows proper formatting rules.
        """
        # RFC 1123 hostname validation
        if not v:
            raise ValueError("Hostname cannot be empty")

        # Basic hostname validation
        hostname_pattern = re.compile(
            r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"  # pylint: disable=line-too-long
        )
        if not hostname_pattern.match(v):
            raise ValueError("Invalid hostname format")

        return v

    @validator("status")
    def validate_status(cls, v):  # pylint: disable=no-self-argument
        """
        Validate that the system status is one of the allowed values.

        Allowed values are: Active, Inactive, Maintenance.
        """
        valid_statuses = ["Active", "Inactive", "Maintenance"]
        if v not in valid_statuses:
            raise ValueError(f"Status must be one of: {', '.join(valid_statuses)}")
        return v

    @validator("environment")
    def validate_environment(cls, v):  # pylint: disable=no-self-argument
        """
        Validate that the environment type is one of the allowed values.

        Allowed values are: Production, Staging, Development, Testing.
        """
        if v is None:
            return v

        valid_environments = ["Production", "Staging", "Development", "Testing"]
        if v not in valid_environments:
            raise ValueError(
                f"Environment must be one of: {', '.join(valid_environments)}"
            )
        return v


class SystemResponse(BaseModel):
    """
    Schema for system response data returned after registration or update.
    """

    id: int
    hostname: str
    ip_address: str
    status: str
    registered_at: datetime
    message: str


class GroupResponse(BaseModel):
    """
    Schema for group response data.
    """

    id: int
    name: str
    description: Optional[str] = None


class DistroResponse(BaseModel):
    """
    Schema for distribution response data.
    """

    id: int
    name: str
    version: str


class CredentialResponse(BaseModel):
    """
    Schema for credential response data.
    """

    id: int
    name: str
    type: str


@router.get("/eol-status")
async def get_eol_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """PRA-43: Distro EOL warnings — returns systems grouped by EOL proximity."""
    from datetime import date, timedelta

    today = date.today()
    warning_threshold = today + timedelta(days=90)

    # PRA-281: scope the fleet EOL rollup to the caller's fleet scope so both the
    # listed systems AND the ok/total counts exclude inaccessible systems.
    eol_query = (
        db.query(System, Distro)
        .join(Distro, Distro.id == System.distro_id)
        .filter(System.status != "Decommissioned")
    )
    eol_query = scope_query_by_system(eol_query, db, current_user, System.id)
    systems_with_distro = eol_query.all()

    eol_systems = []
    warning_systems = []
    ok_count = 0

    for system, distro in systems_with_distro:
        eol_date = distro.end_of_life_date
        days_until = (eol_date - today).days

        entry = {
            "system_id": system.id,
            "hostname": system.hostname,
            "distro_name": distro.name,
            "distro_version": distro.version,
            "end_of_life_date": eol_date.isoformat(),
            "days_until_eol": days_until,
        }

        if eol_date < today:
            eol_systems.append(entry)
        elif eol_date <= warning_threshold:
            warning_systems.append(entry)
        else:
            ok_count += 1

    # Sort: most critical first
    eol_systems.sort(key=lambda x: x["days_until_eol"])
    warning_systems.sort(key=lambda x: x["days_until_eol"])

    return {
        "eol_systems": eol_systems,
        "warning_systems": warning_systems,
        "ok_systems_count": ok_count,
        "total_checked": len(systems_with_distro),
    }


@router.post(
    "/add-system", response_model=SystemResponse, status_code=status.HTTP_201_CREATED
)
async def add_system(
    system: SystemCreate,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Add a new system to the database.

    This endpoint registers a new Linux system in the inventory with validation for:
    - Required fields
    - Format validation (valid IP/hostname)
    - Duplicate detection
    - Reference integrity

    It also handles the initial setup workflow including:
    - Status tracking
    - Default group assignment
    - Initial metadata population
    - Registration confirmation
    """
    # Validate referenced entities exist
    distro = db.query(Distro).filter(Distro.id == system.distro_id).first()
    if not distro:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Distribution with ID {system.distro_id} not found",
        )

    group = db.query(Group).filter(Group.id == system.group_id).first()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Group with ID {system.group_id} not found",
        )

    credential = (
        db.query(Credential).filter(Credential.id == system.credentials_id).first()
    )
    if not credential:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Credential with ID {system.credentials_id} not found",
        )

    # Duplicate detection - check if system with same hostname or IP already exists
    existing_system = (
        db.query(System)
        .filter(
            or_(
                System.hostname == system.hostname,
                System.ip_address == str(system.ip_address),
            )
        )
        .first()
    )

    # Handle re-registration or duplicate
    if existing_system:
        # If system is marked as decommissioned, allow re-registration
        if existing_system.status == "Decommissioned":
            # PRA-133: reactivating a decommissioned row moves it from
            # not-counted (Decommissioned is excluded from the active count) to a
            # counted status, so it increases active managed hosts by one. Gate
            # it on the cap exactly like a brand-new host; the create route only
            # accepts Active/Inactive/Maintenance, all of which count.
            license_service.assert_can_add_host(db, actor_user_id=current_user.id)

            # Get the OS version from the distro
            selected_distro = (
                db.query(Distro).filter(Distro.id == system.distro_id).first()
            )

            # Update the existing system instead of creating a new one
            existing_system.distro_id = system.distro_id
            existing_system.os_version = (
                selected_distro.version
            )  # Use version from the distro
            existing_system.status = system.status
            existing_system.group_id = system.group_id
            existing_system.credentials_id = system.credentials_id
            existing_system.update_policy = system.update_policy
            # PRA-119: re-attach the default policy if none was set previously
            if existing_system.ssh_security_policy_id is None:
                _default_policy = (
                    db.query(SSHSecurityPolicy)
                    .filter(SSHSecurityPolicy.name == "Default")
                    .first()
                )
                if _default_policy:
                    existing_system.ssh_security_policy_id = _default_policy.id
            existing_system.registered_at = datetime.utcnow()
            existing_system.registered_by = current_user.id
            existing_system.updated_at = datetime.utcnow()

            record_audit(
                db,
                system_id=existing_system.id,
                user_id=current_user.id,
                operation="create",
                audit_type="lifecycle",
                old_value="Decommissioned",
                new_value=snapshot_system(existing_system),
            )

            db.commit()
            db.refresh(existing_system)

            return {
                "id": existing_system.id,
                "hostname": existing_system.hostname,
                "ip_address": str(existing_system.ip_address),
                "status": existing_system.status,
                "registered_at": existing_system.registered_at,
                "message": "System successfully re-registered",
            }

        # Determine if it's a hostname or IP conflict
        if existing_system.hostname == system.hostname:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A system with hostname '{system.hostname}' already exists",
            )

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A system with IP address '{system.ip_address}' already exists",
        )

    try:
        # Get the OS version from the distro
        selected_distro = db.query(Distro).filter(Distro.id == system.distro_id).first()

        # PRA-119: attach the default SSH security policy (enforces host key verification)
        default_policy = (
            db.query(SSHSecurityPolicy)
            .filter(SSHSecurityPolicy.name == "Default")
            .first()
        )

        # PRA-133: enforce the edition host cap before creating a NEW managed
        # host. Re-registering a decommissioned row (handled above) reuses the
        # existing System, so it is not gated here. Unlimited (licensed) caps and
        # the test enterprise default pass through.
        license_service.assert_can_add_host(db, actor_user_id=current_user.id)

        # Create new system record
        db_system = System(
            hostname=system.hostname,
            ip_address=str(system.ip_address),
            distro_id=system.distro_id,
            os_version=selected_distro.version,  # Use version from the distro
            status=system.status,
            group_id=system.group_id,
            credentials_id=system.credentials_id,
            ssh_security_policy_id=default_policy.id if default_policy else None,
            update_policy=system.update_policy,
            registered_at=datetime.utcnow(),
            registered_by=current_user.id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )

        db.add(db_system)
        db.flush()  # Flush to get the ID without committing

        # Create initial system metadata
        system_metadata = SystemMetadata(
            system_id=db_system.id,
            environment_type=system.environment or "Production",
            owner_contact=current_user.email,
            ssh_port=22,  # Default SSH port
            connection_status="Pending",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )

        db.add(system_metadata)
        db.flush()

        record_audit(
            db,
            system_id=db_system.id,
            user_id=current_user.id,
            operation="create",
            audit_type="system",
            old_value=None,
            new_value=snapshot_system(db_system),
        )

        db.commit()
        db.refresh(db_system)

        # Notification: system added (PRA-99)
        create_notification(
            db,
            type="system_added",
            title=f"System added: {db_system.hostname}",
            message=f"New system '{db_system.hostname}' ({db_system.ip_address}) registered",
            severity="info",
        )

        return {
            "id": db_system.id,
            "hostname": db_system.hostname,
            "ip_address": str(db_system.ip_address),
            "status": db_system.status,
            "registered_at": db_system.registered_at,
            "message": "System successfully registered",
        }
    except IntegrityError as e:
        db.rollback()
        if "unique constraint" in str(e.orig).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A system with this hostname already exists",
            ) from e
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid data - ensure all referenced IDs (distro, group, credentials) exist",
        ) from e
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while registering the system: {str(e)}",
        ) from e


@router.get("/groups", response_model=List[GroupResponse])
async def get_groups(
    current_user: User = Depends(get_current_user),  # pylint: disable=unused-argument
    db: Session = Depends(get_db),
):
    """
    Get all available system groups.
    """
    groups = db.query(Group).all()
    return groups


@router.get("/distros", response_model=List[DistroResponse])
async def get_distros(
    current_user: User = Depends(get_current_user),  # pylint: disable=unused-argument
    db: Session = Depends(get_db),
):
    """
    Get all available distributions.
    """
    distros = db.query(Distro).all()
    return distros


@router.get("/credentials", response_model=List[CredentialResponse])
async def get_credentials(
    current_user: User = Depends(get_current_user),  # pylint: disable=unused-argument
    db: Session = Depends(get_db),
):
    """
    Get all available credentials.
    """
    credentials = db.query(Credential).all()
    return credentials


class SystemListResponse(BaseModel):
    """
    Schema for system list response data.
    """

    id: int
    hostname: str
    ip_address: str
    status: str
    os_version: str
    registered_at: datetime
    environment_type: Optional[str] = None
    group_id: int
    group_name: str
    distro_name: str
    ca_trust_deployed: bool = False
    transport_preference: str = "auto"
    # PRA-348: last successful package scan time — durable "Last checked" source for
    # the Available Updates page so it rehydrates across navigation/reload.
    last_audited: Optional[datetime] = None
    tags: list = []


@router.get("/all", response_model=List[SystemListResponse])
async def get_all_systems(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get all systems in the inventory.

    Returns a list of all registered systems with their basic information.
    """
    # Query systems with joined related data
    systems_query = (
        db.query(
            System.id,
            System.hostname,
            System.ip_address,
            System.status,
            System.os_version,
            System.registered_at,
            System.ca_trust_deployed,
            System.transport_preference,
            System.last_audited,
            System.group_id,
            SystemMetadata.environment_type,
            Group.name.label("group_name"),
            Distro.name.label("distro_name"),
        )
        .join(Group, System.group_id == Group.id)
        .join(Distro, System.distro_id == Distro.id)
        .outerjoin(SystemMetadata, System.id == SystemMetadata.system_id)
    )
    # PRA-281: the inventory list is scoped to the caller's fleet scope.
    systems_query = scope_query_by_system(systems_query, db, current_user, System.id)
    systems = systems_query.all()

    # Query tag associations for all systems
    system_ids = [s.id for s in systems]
    tag_rows = (
        db.query(
            system_tag.c.system_id,
            Tag.id.label("tag_id"),
            Tag.name.label("tag_name"),
            Tag.color.label("tag_color"),
        )
        .join(Tag, system_tag.c.tag_id == Tag.id)
        .filter(system_tag.c.system_id.in_(system_ids))
        .all()
        if system_ids
        else []
    )

    # Build system_id -> tags mapping
    tags_by_system: Dict[int, list] = {}
    for row in tag_rows:
        tags_by_system.setdefault(row.system_id, []).append(
            {"id": row.tag_id, "name": row.tag_name, "color": row.tag_color}
        )

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
                "environment_type": system.environment_type,
                "group_id": system.group_id,
                "group_name": system.group_name,
                "distro_name": system.distro_name,
                "ca_trust_deployed": system.ca_trust_deployed,
                "transport_preference": system.transport_preference,
                "last_audited": system.last_audited,
                "tags": tags_by_system.get(system.id, []),
            }
        )

    return result


# Registered BEFORE /{system_id}/... so the literal path wins. FastAPI
# routes match in declaration order; without this the bulk endpoint
# would be shadowed by the per-host one when "agent-health" is parsed
# as a system_id (and 422'd). Helpers (_compute_badge,
# _agent_health_payload) live further down — Python resolves them at
# request time so forward reference here is fine.
@router.get("/agent-health", response_model=Dict[str, Any])
async def list_agent_health(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Bulk per-system agent-health snapshot for the systems list
    badge. Returns ``{"systems": [...]}`` so callers can map by id.

    One broker call per host, fanned out via ``asyncio.gather`` so a
    larger fleet still finishes in roughly one round-trip. A single
    host's broker error degrades that host to ``state="unknown"`` —
    it does NOT 500 the whole batch.
    """
    import asyncio

    from ...services.broker_client import BrokerClient, TunnelHealth

    # PRA-281: only report agent health for systems in the caller's fleet scope.
    ah_query = db.query(System.id, System.transport_preference)
    ah_query = scope_query_by_system(ah_query, db, current_user, System.id)
    systems = ah_query.all()
    if not systems:
        return {"systems": []}

    async def _one(broker, sid):
        try:
            return await broker.health(sid)
        except Exception:  # pylint: disable=broad-except
            # Belt + suspenders — BrokerClient.health() already
            # degrades httpx errors to state="unknown", but a bug
            # there must NOT take down the whole list.
            return TunnelHealth(system_id=sid, state="unknown")

    async with BrokerClient() as broker:
        healths = await asyncio.gather(*[_one(broker, s.id) for s in systems])

    by_id = {h.system_id: h for h in healths}
    out = []
    for s in systems:
        h = by_id.get(s.id) or TunnelHealth(system_id=s.id, state="unknown")
        badge = _compute_badge(s.transport_preference, h.state)
        out.append(
            {
                "system_id": s.id,
                "transport_preference": s.transport_preference,
                "agent_health": {
                    "state": h.state,
                    "tunnel_session_id": h.tunnel_session_id,
                    "since_seconds": h.since_seconds,
                    "last_heartbeat_age_seconds": h.last_heartbeat_age_seconds,
                },
                "effective_transport": badge["effective_transport"],
                "badge_state": badge["badge_state"],
            }
        )
    return {"systems": out}


@router.delete(
    "/{system_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_system_access("admin", "maintainer"))],
)
async def delete_system(
    system_id: int,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Delete a system from the inventory.

    This endpoint removes a system from the inventory. It requires delete_systems permission.
    """
    # Find the system
    system = db.query(System).filter(System.id == system_id).first()

    if not system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System with ID {system_id} not found",
        )

    try:
        # Capture system state before deletion for the audit trail
        pre_delete_snapshot = snapshot_system(system)
        deleted_hostname = system.hostname

        record_audit(
            db,
            system_id=system.id,
            user_id=current_user.id,
            operation="delete",
            audit_type="lifecycle",
            old_value=pre_delete_snapshot,
            new_value=None,
        )

        # Delete associated metadata first (due to foreign key constraint)
        metadata = (
            db.query(SystemMetadata)
            .filter(SystemMetadata.system_id == system_id)
            .first()
        )
        if metadata:
            db.delete(metadata)

        # Delete the system (audit rows retain history via ON DELETE SET NULL)
        db.delete(system)
        db.commit()

        # Notification: system removed (PRA-99)
        create_notification(
            db,
            type="system_removed",
            title=f"System removed: {deleted_hostname}",
            message=f"System '{deleted_hostname}' was deleted from inventory",
            severity="warning",
        )

        return None
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while deleting the system: {str(e)}",
        ) from e


@router.put(
    "/{system_id}",
    response_model=dict,
    dependencies=[Depends(require_system_access("admin", "maintainer"))],
)
async def update_system(
    system_id: int,
    system: SystemCreate,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Update an existing system in the inventory.

    This endpoint updates a system's information in the inventory with validation for:
    - Required fields
    - Format validation (valid IP/hostname)
    - Duplicate detection
    - Reference integrity
    """
    # Find the system to update
    db_system = db.query(System).filter(System.id == system_id).first()
    if not db_system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System with ID {system_id} not found",
        )

    # Validate referenced entities exist
    distro = db.query(Distro).filter(Distro.id == system.distro_id).first()
    if not distro:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Distribution with ID {system.distro_id} not found",
        )

    group = db.query(Group).filter(Group.id == system.group_id).first()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Group with ID {system.group_id} not found",
        )

    credential = (
        db.query(Credential).filter(Credential.id == system.credentials_id).first()
    )
    if not credential:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Credential with ID {system.credentials_id} not found",
        )

    # Check for hostname/IP conflicts with other systems
    hostname_conflict = (
        db.query(System)
        .filter(System.hostname == system.hostname, System.id != system_id)
        .first()
    )

    if hostname_conflict:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Another system with hostname '{system.hostname}' already exists",
        )

    ip_conflict = (
        db.query(System)
        .filter(System.ip_address == str(system.ip_address), System.id != system_id)
        .first()
    )

    if ip_conflict:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Another system with IP address '{system.ip_address}' already exists",
        )

    try:
        # Get the OS version from the distro
        selected_distro = db.query(Distro).filter(Distro.id == system.distro_id).first()

        # Capture prior values to diff for audit logging
        prior = {
            "hostname": db_system.hostname,
            "ip_address": (str(db_system.ip_address) if db_system.ip_address else None),
            "distro_id": db_system.distro_id,
            "os_version": db_system.os_version,
            "status": db_system.status,
            "group_id": db_system.group_id,
            "credentials_id": db_system.credentials_id,
            "update_policy": db_system.update_policy,
        }
        new_vals = {
            "hostname": system.hostname,
            "ip_address": str(system.ip_address),
            "distro_id": system.distro_id,
            "os_version": selected_distro.version,
            "status": system.status,
            "group_id": system.group_id,
            "credentials_id": system.credentials_id,
            "update_policy": system.update_policy,
        }
        operation_map = {
            "status": "status_change",
            "group_id": "group_change",
            "credentials_id": "credential_assign",
        }

        # Update system fields
        db_system.hostname = system.hostname
        db_system.ip_address = str(system.ip_address)
        db_system.distro_id = system.distro_id
        db_system.os_version = selected_distro.version  # Use version from the distro
        db_system.status = system.status
        db_system.group_id = system.group_id
        db_system.credentials_id = system.credentials_id
        db_system.update_policy = system.update_policy
        db_system.updated_at = datetime.utcnow()

        for field, old_val in prior.items():
            new_val = new_vals[field]
            if str(old_val) != str(new_val):
                record_audit(
                    db,
                    system_id=db_system.id,
                    user_id=current_user.id,
                    operation=operation_map.get(field, "update"),
                    audit_type=field,
                    old_value=old_val,
                    new_value=new_val,
                )

        # Update system metadata if it exists
        metadata = (
            db.query(SystemMetadata)
            .filter(SystemMetadata.system_id == system_id)
            .first()
        )
        if metadata and system.environment:
            if metadata.environment_type != system.environment:
                record_audit(
                    db,
                    system_id=db_system.id,
                    user_id=current_user.id,
                    operation="update",
                    audit_type="environment",
                    old_value=metadata.environment_type,
                    new_value=system.environment,
                )
            metadata.environment_type = system.environment
            metadata.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(db_system)

        # Get updated system with related data for response
        group = db.query(Group).filter(Group.id == db_system.group_id).first()
        distro = db.query(Distro).filter(Distro.id == db_system.distro_id).first()
        metadata = (
            db.query(SystemMetadata)
            .filter(SystemMetadata.system_id == db_system.id)
            .first()
        )

        # Build response
        result = {
            "id": db_system.id,
            "hostname": db_system.hostname,
            "ip_address": str(db_system.ip_address),
            "status": db_system.status,
            "os_version": db_system.os_version,
            "registered_at": db_system.registered_at,
            "update_policy": db_system.update_policy,
            "group": {
                "id": group.id,
                "name": group.name,
                "description": group.description,
            },
            "distribution": {
                "id": distro.id,
                "name": distro.name,
                "version": distro.version,
            },
            "message": "System successfully updated",
        }

        # Add metadata if available
        if metadata:
            result["metadata"] = {
                "environment_type": metadata.environment_type,
                "owner_contact": metadata.owner_contact,
                "ssh_port": metadata.ssh_port,
                "connection_status": metadata.connection_status,
                "cpu_arch": metadata.cpu_arch,
                "cpu_cores": metadata.cpu_cores,
                "memory_total": metadata.memory_total,
                "disk_total": metadata.disk_total,
                "maintenance_window": metadata.maintenance_window,
                "location": metadata.location,
                "last_connection": metadata.last_connection,
            }

        return result
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while updating the system: {str(e)}",
        ) from e


@router.get(
    "/{system_id}",
    response_model=dict,
    dependencies=[Depends(require_system_access())],
)
async def get_system_details(
    system_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get detailed information about a specific system.

    Returns comprehensive information about the specified system, including
    metadata, group, distribution, and credentials information.
    """
    # Query the system with all related data
    system = db.query(System).filter(System.id == system_id).first()

    if not system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System with ID {system_id} not found",
        )

    # Get related data
    group = db.query(Group).filter(Group.id == system.group_id).first()
    distro = db.query(Distro).filter(Distro.id == system.distro_id).first()
    metadata = (
        db.query(SystemMetadata).filter(SystemMetadata.system_id == system.id).first()
    )

    # Get tags for this system
    system_tags = [{"id": t.id, "name": t.name, "color": t.color} for t in system.tags]

    # Build response
    result = {
        "id": system.id,
        "hostname": system.hostname,
        "ip_address": str(system.ip_address),
        "status": system.status,
        "os_version": system.os_version,
        "registered_at": system.registered_at,
        "update_policy": system.update_policy,
        "ca_trust_deployed": system.ca_trust_deployed,
        "ca_trust_deployed_at": (
            system.ca_trust_deployed_at.isoformat() + "Z"
            if system.ca_trust_deployed_at
            else None
        ),
        "principals_hook_deployed": system.principals_hook_deployed,
        "principals_hook_deployed_at": (
            system.principals_hook_deployed_at.isoformat() + "Z"
            if system.principals_hook_deployed_at
            else None
        ),
        "transport_preference": system.transport_preference,
        "group": {"id": group.id, "name": group.name, "description": group.description},
        "distribution": {
            "id": distro.id,
            "name": distro.name,
            "version": distro.version,
        },
        "tags": system_tags,
    }

    # Add metadata if available
    if metadata:
        result["metadata"] = {
            "environment_type": metadata.environment_type,
            "owner_contact": metadata.owner_contact,
            "ssh_port": metadata.ssh_port,
            "connection_status": metadata.connection_status,
            "cpu_arch": metadata.cpu_arch,
            "cpu_cores": metadata.cpu_cores,
            "memory_total": metadata.memory_total,
            "disk_total": metadata.disk_total,
            "maintenance_window": metadata.maintenance_window,
            "location": metadata.location,
            "last_connection": metadata.last_connection,
        }

    return result


# --------------------------------------------------------------------------
# PRA-153 #4: transport_preference + agent-health surfaces
#
# The internal broker HTTP API at /internal/agent/health/{id} is bound to
# the docker network and not auth'd; the operator UI cannot call it
# directly. These wrappers add the auth + per-host preference + derived
# badge state the UI needs.
# --------------------------------------------------------------------------


_VALID_TRANSPORT_PREFS = ("auto", "ssh", "agent")


class _TransportPreferenceUpdate(BaseModel):
    """Body schema for PATCH /{system_id}/transport-preference."""

    transport_preference: str = Field(...)

    @validator("transport_preference")
    def _validate(cls, v):  # pylint: disable=no-self-argument
        if v not in _VALID_TRANSPORT_PREFS:
            raise ValueError(
                f"transport_preference must be one of: "
                f"{', '.join(_VALID_TRANSPORT_PREFS)}"
            )
        return v


def _compute_badge(pref: str, health_state: str) -> Dict[str, Optional[str]]:
    """Map (preference, broker health state) → (effective_transport,
    badge_state) per the PRA-153 #4 design lock.

    badge_state vocabulary (UI labels in parens):
        ssh_forced         — pref=ssh, anything                ("SSH forced")
        agent_connected    — pref=auto + healthy               ("Agent connected")
        ssh_fallback       — pref=auto + stale/unregistered    ("SSH fallback")
        agent_forced       — pref=agent + healthy              ("Agent forced")
        agent_unavailable  — pref=agent + stale/unregistered   ("Agent unavailable")
        unknown            — broker health lookup itself failed
                             (state="unknown") for either auto or agent.
                             Per the design lock we MUST NOT silently
                             imply agent is usable when we couldn't
                             check.
    """
    if pref == "ssh":
        return {"effective_transport": "ssh", "badge_state": "ssh_forced"}
    if health_state == "unknown":
        # auto + unknown still routes through SSH at the factory level
        # (is_usable=False), but the badge stays "unknown" so the UI
        # doesn't claim we know the transport state.
        effective = None if pref == "agent" else "ssh"
        return {"effective_transport": effective, "badge_state": "unknown"}
    if pref == "agent":
        if health_state == "healthy":
            return {"effective_transport": "agent", "badge_state": "agent_forced"}
        return {"effective_transport": None, "badge_state": "agent_unavailable"}
    # pref == "auto"
    if health_state == "healthy":
        return {"effective_transport": "agent", "badge_state": "agent_connected"}
    return {"effective_transport": "ssh", "badge_state": "ssh_fallback"}


def _agent_health_payload(system: System, health) -> Dict[str, Any]:
    """Build the per-host agent-health response shape."""
    pref = system.transport_preference
    badge = _compute_badge(pref, health.state)
    return {
        "system_id": system.id,
        "transport_preference": pref,
        "agent_health": {
            "state": health.state,
            "tunnel_session_id": health.tunnel_session_id,
            "since_seconds": health.since_seconds,
            "last_heartbeat_age_seconds": health.last_heartbeat_age_seconds,
        },
        "effective_transport": badge["effective_transport"],
        "badge_state": badge["badge_state"],
    }


@router.get(
    "/{system_id}/agent-health",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access())],
)
async def get_agent_health(
    system_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Per-host agent-health snapshot for the host detail badge.

    Auth: any authenticated user (read-only — preference is part of
    the host's public-to-this-tenant inventory shape, and operators
    need to see badge state regardless of role).
    """
    from ...services.broker_client import BrokerClient

    system = db.query(System).filter(System.id == system_id).first()
    if system is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System with ID {system_id} not found",
        )
    async with BrokerClient() as broker:
        health = await broker.health(system_id)
    return _agent_health_payload(system, health)


@router.patch(
    "/{system_id}/transport-preference",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access("admin"))],
)
async def update_transport_preference(
    system_id: int,
    body: _TransportPreferenceUpdate,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Update ``System.transport_preference`` (admin-only).

    PRA-153 #4 lock: maintainers can SEE the preference + agent-health
    but cannot change it in this slice. Bulk editing is also out of
    scope — one host at a time.

    Audit-logged via ``record_audit`` so the change shows up in the
    host's history alongside other lifecycle events.
    """
    system = db.query(System).filter(System.id == system_id).first()
    if system is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System with ID {system_id} not found",
        )

    new_pref = body.transport_preference
    old_pref = system.transport_preference
    if new_pref != old_pref:
        system.transport_preference = new_pref
        record_audit(
            db,
            system_id=system.id,
            user_id=current_user.id,
            operation="update",
            audit_type="transport_preference",
            old_value=old_pref,
            new_value=new_pref,
        )
        db.commit()
        db.refresh(system)

    return {
        "system_id": system.id,
        "hostname": system.hostname,
        "transport_preference": system.transport_preference,
    }
