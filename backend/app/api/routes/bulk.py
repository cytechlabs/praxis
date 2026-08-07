"""
Bulk operations routes module.

This module provides API endpoints for performing fleet-wide bulk actions
on systems, including status changes, group reassignment, credential
assignment, deletion, and bulk import.
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import or_, text
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role
from ...db.command_execution_models import (
    CommandExecutionQueue,
    CommandExecutionResult,
    CommandExecutionSystemPolicy,
)
from ...db.models import (
    CommandValidationLog,
    Credential,
    Distro,
    Group,
    Package,
    PackageHistory,
    PackageUpdate,
    RepoSource,
    System,
    SystemAudit,
    SystemMetadata,
    Tag,
    User,
    system_tag,
)
from ...db.session import get_db
from ...db.ssh_security_models import SSHHostKey, SSHSecurityLog
from ...services import fleet_operation_service
from ...services.access_authorization_service import scoped_system_ids
from ...services.notification_service import create_notification
from ...services.system_audit_service import record_audit, snapshot_system

router = APIRouter(redirect_slashes=False)


def _enforce_batch_scope(db: Session, current_user: User, system_ids) -> None:
    """PRA-281: reject the WHOLE bulk request with a non-disclosing 404 if any
    requested system is outside the caller's fleet scope — BEFORE
    ``fleet_operation_service.start_operation``, any DB mutation/delete,
    dependent-row delete, audit row, notification, or fleet-operation result.

    A scoped caller (``scoped_system_ids(...) is not None``) may operate only on
    systems entirely within their grants; a missing OR out-of-scope id is
    indistinguishable (both 404), so no hidden hostname / old value / group name
    / credential name / result row / fleet-op parameter leaks, and mixed batches
    are never partially applied. Empty scope fails closed (no id is in scope).
    Tenant-wide admins (scope ``None``) are unchanged.
    """
    scope = scoped_system_ids(db, current_user)
    if scope is None:
        return
    for sid in system_ids:
        if sid not in scope:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="System not found"
            )


def _require_tenant_wide_admin(db: Session, current_user: User, detail: str) -> None:
    """PRA-281: refuse a scoped caller with 403 before any global lookup, fleet
    operation, DB write, audit, or notification. Tenant-wide admins unchanged."""
    if scoped_system_ids(db, current_user) is not None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


VALID_STATUSES = ["Active", "Inactive", "Maintenance", "Decommissioned"]
VALID_ENVIRONMENTS = ["Production", "Staging", "Development", "Testing"]
HOSTNAME_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)


# --- Pydantic Schemas ---


class BulkStatusUpdate(BaseModel):
    system_ids: List[int]
    status: str  # Active, Inactive, Maintenance, Decommissioned


class BulkGroupUpdate(BaseModel):
    system_ids: List[int]
    group_id: int


class BulkDelete(BaseModel):
    system_ids: List[int]


class BulkCredentialAssign(BaseModel):
    system_ids: List[int]
    credential_id: int
    test_connection: bool = False


class BulkImportSystem(BaseModel):
    hostname: str
    ip_address: str
    distro: Optional[str] = None  # distro name, e.g. "Ubuntu"
    distro_id: Optional[int] = None  # or ID directly
    status: str = "Active"
    group: Optional[str] = None  # group name, e.g. "US-East"
    group_id: Optional[int] = None  # or ID directly
    credential: Optional[str] = None  # credential name, e.g. "default"
    credentials_id: Optional[int] = None  # or ID directly
    environment: Optional[str] = "Production"
    tags: Optional[List[str]] = None  # tag names
    tag_ids: Optional[List[int]] = None  # or tag IDs directly


class BulkImportRequest(BaseModel):
    systems: List[BulkImportSystem]
    dry_run: bool = False


class BulkCommandRequest(BaseModel):
    system_ids: List[int]
    command: str


# --- Endpoints ---


@router.put("/status")
def bulk_status_update(
    payload: BulkStatusUpdate,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Bulk update the status of multiple systems.

    Validates all system IDs exist and the status value is valid,
    then updates each system and returns per-system results.
    """
    if payload.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {', '.join(VALID_STATUSES)}",
        )

    if not payload.system_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="system_ids cannot be empty",
        )

    # PRA-281: fail the whole batch (non-disclosing 404) if any system is out of
    # scope, before the fleet-operation row / mutation / audit / notification.
    _enforce_batch_scope(db, current_user, payload.system_ids)

    fleet_op_id = fleet_operation_service.start_operation(
        operation_type="bulk_status_update",
        user_id=current_user.id,
        target_count=len(payload.system_ids),
        parameters={"status": payload.status, "system_ids": payload.system_ids},
    )

    results = []
    for system_id in payload.system_ids:
        system = db.query(System).filter(System.id == system_id).first()
        if not system:
            msg = f"System with ID {system_id} not found"
            results.append({"system_id": system_id, "status": "error", "message": msg})
            fleet_operation_service.record_result(
                fleet_op_id, system_id, "failure", msg
            )
            continue

        old_status = system.status
        system.status = payload.status
        system.updated_at = datetime.utcnow()
        if old_status != payload.status:
            record_audit(
                db,
                system_id=system.id,
                user_id=current_user.id,
                operation="bulk_status_update",
                audit_type="status",
                old_value=old_status,
                new_value=payload.status,
            )
        results.append(
            {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "updated",
                "old_status": old_status,
                "new_status": payload.status,
            }
        )
        fleet_operation_service.record_result(fleet_op_id, system_id, "success")

    db.commit()

    updated_count = sum(1 for r in results if r["status"] == "updated")
    error_count = len(payload.system_ids) - updated_count
    fleet_operation_service.complete_operation(fleet_op_id, updated_count, error_count)

    # Notification: bulk operation complete (PRA-99)
    create_notification(
        db,
        type="bulk_operation_complete",
        title="Bulk status update complete",
        message=f"Updated {updated_count} systems to '{payload.status}', {error_count} errors",
        severity="info" if error_count == 0 else "warning",
    )

    return {
        "total": len(payload.system_ids),
        "updated": updated_count,
        "errors": error_count,
        "results": results,
        "fleet_operation_id": fleet_op_id,
    }


@router.put("/group")
def bulk_group_update(
    payload: BulkGroupUpdate,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Bulk reassign systems to a different group.

    Validates the target group exists, then updates all specified systems.
    """
    # PRA-281: scope-check the whole target batch BEFORE the group lookup (so a
    # hidden-host request cannot probe group taxonomy) and before any mutation.
    if payload.system_ids:
        _enforce_batch_scope(db, current_user, payload.system_ids)

    group = db.query(Group).filter(Group.id == payload.group_id).first()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group with ID {payload.group_id} not found",
        )

    if not payload.system_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="system_ids cannot be empty",
        )

    fleet_op_id = fleet_operation_service.start_operation(
        operation_type="bulk_group_update",
        user_id=current_user.id,
        target_count=len(payload.system_ids),
        parameters={"group_id": payload.group_id, "system_ids": payload.system_ids},
    )

    prior_groups = {
        row[0]: row[1]
        for row in db.query(System.id, System.group_id)
        .filter(System.id.in_(payload.system_ids))
        .all()
    }
    existing_ids = set(prior_groups.keys())

    updated = (
        db.query(System)
        .filter(System.id.in_(payload.system_ids))
        .update(
            {System.group_id: payload.group_id, System.updated_at: datetime.utcnow()},
            synchronize_session="fetch",
        )
    )

    for sid, old_group_id in prior_groups.items():
        if old_group_id != payload.group_id:
            record_audit(
                db,
                system_id=sid,
                user_id=current_user.id,
                operation="bulk_group_update",
                audit_type="group_id",
                old_value=old_group_id,
                new_value=payload.group_id,
            )

    db.commit()

    for sid in payload.system_ids:
        if sid in existing_ids:
            fleet_operation_service.record_result(fleet_op_id, sid, "success")
        else:
            fleet_operation_service.record_result(
                fleet_op_id, sid, "failure", f"System {sid} not found"
            )

    fail = len(payload.system_ids) - updated
    fleet_operation_service.complete_operation(fleet_op_id, updated, fail)

    # Notification: bulk operation complete (PRA-99)
    create_notification(
        db,
        type="bulk_operation_complete",
        title="Bulk group update complete",
        message=f"Moved {updated} systems to group '{group.name}', {fail} errors",
        severity="info" if fail == 0 else "warning",
    )

    return {
        "total": len(payload.system_ids),
        "updated": updated,
        "group": {"id": group.id, "name": group.name},
        "fleet_operation_id": fleet_op_id,
    }


@router.delete("/systems")
def bulk_delete_systems(
    payload: BulkDelete,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Bulk delete systems and their associated metadata.

    Cascade rules handle system_tag cleanup automatically.
    """
    if not payload.system_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="system_ids cannot be empty",
        )

    # PRA-281: this is destructive — fail the whole batch (non-disclosing 404) if
    # any system is out of scope, BEFORE the fleet-operation row, snapshots,
    # delete audit rows, dependent-row deletes, system_tag deletes, or the
    # system deletes.
    _enforce_batch_scope(db, current_user, payload.system_ids)

    fleet_op_id = fleet_operation_service.start_operation(
        operation_type="bulk_delete",
        user_id=current_user.id,
        target_count=len(payload.system_ids),
        parameters={"system_ids": payload.system_ids},
    )

    existing_systems = db.query(System).filter(System.id.in_(payload.system_ids)).all()
    existing_ids = {s.id for s in existing_systems}

    # Capture snapshots and write delete audit rows BEFORE removal
    for sys_obj in existing_systems:
        record_audit(
            db,
            system_id=sys_obj.id,
            user_id=current_user.id,
            operation="bulk_delete",
            audit_type="lifecycle",
            old_value=snapshot_system(sys_obj),
            new_value=None,
        )
    db.flush()

    # Delete all dependent records first (foreign key constraints)
    ids = payload.system_ids
    # Delete from ORM models with system_id FK
    for model in [
        SSHSecurityLog,
        SSHHostKey,
        CommandExecutionResult,
        CommandExecutionSystemPolicy,
        CommandExecutionQueue,
        CommandValidationLog,
        PackageHistory,
        PackageUpdate,
        Package,
        RepoSource,
        SystemMetadata,
    ]:
        db.query(model).filter(model.system_id.in_(ids)).delete(
            synchronize_session="fetch"
        )

    # Delete from distribution tables if they exist
    for table_name in ["system_detection_results", "system_capabilities"]:
        exists = db.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
                "WHERE table_name = :t)"
            ),
            {"t": table_name},
        ).scalar()
        if exists:
            db.execute(
                text(f"DELETE FROM {table_name} WHERE system_id = ANY(:ids)"),
                {"ids": ids},
            )

    # Delete system_tag entries
    db.execute(system_tag.delete().where(system_tag.c.system_id.in_(ids)))

    deleted = (
        db.query(System).filter(System.id.in_(ids)).delete(synchronize_session="fetch")
    )

    db.commit()

    for sid in payload.system_ids:
        if sid in existing_ids:
            fleet_operation_service.record_result(fleet_op_id, None, "success")
        else:
            fleet_operation_service.record_result(
                fleet_op_id, None, "failure", f"System {sid} not found"
            )
    not_found = len(payload.system_ids) - deleted
    fleet_operation_service.complete_operation(fleet_op_id, deleted, not_found)

    # Notification: bulk operation complete (PRA-99)
    create_notification(
        db,
        type="bulk_operation_complete",
        title="Bulk delete complete",
        message=f"Deleted {deleted} systems, {not_found} not found",
        severity="info" if not_found == 0 else "warning",
    )

    return {
        "total": len(payload.system_ids),
        "deleted": deleted,
        "fleet_operation_id": fleet_op_id,
    }


@router.put("/credentials")
def bulk_credential_assign(
    payload: BulkCredentialAssign,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Bulk assign a credential to multiple systems.

    Validates the credential exists, then updates credentials_id
    on all specified systems and returns per-system results.
    """
    # PRA-281: attaching a credential requires seeing the credential's FULL
    # linkage (the scoped credential-visibility model — Slice 10 — gates that at
    # the credentials route and is not reusable here), and a scoped caller could
    # otherwise probe credential ids / names or bind a secret whose linkage they
    # cannot see. Conservative default: tenant-wide-admin-only for scoped callers,
    # BEFORE the credential lookup / fleet operation / mutation / audit.
    _require_tenant_wide_admin(
        db,
        current_user,
        "Bulk credential assignment requires tenant-wide admin access",
    )

    credential = (
        db.query(Credential).filter(Credential.id == payload.credential_id).first()
    )
    if not credential:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential with ID {payload.credential_id} not found",
        )

    if not payload.system_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="system_ids cannot be empty",
        )

    fleet_op_id = fleet_operation_service.start_operation(
        operation_type="bulk_credential_assign",
        user_id=current_user.id,
        target_count=len(payload.system_ids),
        parameters={
            "credential_id": payload.credential_id,
            "system_ids": payload.system_ids,
        },
    )

    results = []
    for system_id in payload.system_ids:
        system = db.query(System).filter(System.id == system_id).first()
        if not system:
            msg = f"System with ID {system_id} not found"
            results.append({"system_id": system_id, "status": "error", "message": msg})
            fleet_operation_service.record_result(
                fleet_op_id, system_id, "failure", msg
            )
            continue

        old_cred_id = system.credentials_id
        system.credentials_id = payload.credential_id
        system.updated_at = datetime.utcnow()
        if old_cred_id != payload.credential_id:
            record_audit(
                db,
                system_id=system.id,
                user_id=current_user.id,
                operation="bulk_credential_assign",
                audit_type="credentials_id",
                old_value=old_cred_id,
                new_value=payload.credential_id,
            )
        results.append(
            {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "updated",
                "credential": credential.name,
            }
        )
        fleet_operation_service.record_result(fleet_op_id, system_id, "success")

    db.commit()

    updated_count = sum(1 for r in results if r["status"] == "updated")
    error_count = len(payload.system_ids) - updated_count
    fleet_operation_service.complete_operation(fleet_op_id, updated_count, error_count)

    # Notification: bulk operation complete (PRA-99)
    create_notification(
        db,
        type="bulk_operation_complete",
        title="Bulk credential assign complete",
        message=(
            f"Assigned credential '{credential.name}' to {updated_count} systems, "
            f"{error_count} errors"
        ),
        severity="info" if error_count == 0 else "warning",
    )

    return {
        "total": len(payload.system_ids),
        "updated": updated_count,
        "errors": error_count,
        "credential": {"id": credential.id, "name": credential.name},
        "results": results,
        "fleet_operation_id": fleet_op_id,
    }


@router.post("/import", status_code=status.HTTP_201_CREATED)
def bulk_import_systems(
    payload: BulkImportRequest,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Bulk import multiple systems at once.

    Validates each system individually. If dry_run is True, returns
    validation results without creating anything. Otherwise, creates
    valid systems and skips invalid ones (partial success).
    """
    # PRA-281: import CREATES systems (with global distro/group/credential/tag
    # attachment) — there is no fleet scope for a system that does not exist yet,
    # and the resolution step probes global credential/group/distro/tag names.
    # Conservative default: tenant-wide-admin-only for scoped callers, BEFORE any
    # global lookup, duplicate check, fleet-operation row, DB write, audit, or
    # notification.
    _require_tenant_wide_admin(
        db, current_user, "Bulk import requires tenant-wide admin access"
    )

    if not payload.systems:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="systems list cannot be empty",
        )

    # Build lookup maps for name-to-ID resolution
    all_distros = {d.id: d for d in db.query(Distro).all()}
    distro_name_map = {}
    distro_versions = {}  # name -> [version, version, ...]
    for d in all_distros.values():
        # Map "almalinux 10" -> distro (name + version, exact match)
        distro_name_map[f"{d.name.lower()} {d.version.lower()}"] = d
        # Track all versions per name for ambiguity detection
        distro_versions.setdefault(d.name.lower(), []).append(d.version)

    all_groups = {g.id: g for g in db.query(Group).all()}
    group_name_map = {g.name.lower(): g for g in all_groups.values()}

    all_credentials = {c.id: c for c in db.query(Credential).all()}
    cred_name_map = {c.name.lower(): c for c in all_credentials.values()}

    all_tags_db = {t.id: t for t in db.query(Tag).all()}
    tag_name_map = {t.name.lower(): t for t in all_tags_db.values()}

    # Get existing hostnames and IPs for duplicate checking
    existing_hostnames = {
        h[0]
        for h in db.query(System.hostname)
        .filter(System.hostname.in_([s.hostname for s in payload.systems]))
        .all()
    }
    existing_ips = {
        str(ip[0])
        for ip in db.query(System.ip_address)
        .filter(System.ip_address.in_([s.ip_address for s in payload.systems]))
        .all()
    }

    # Track hostnames/IPs within the batch to detect intra-batch duplicates
    batch_hostnames = set()
    batch_ips = set()

    results = []
    systems_to_create = []

    for sys_data in payload.systems:
        errors = []

        # Resolve distro: name takes priority, fall back to ID
        resolved_distro_id = sys_data.distro_id
        if sys_data.distro:
            key = sys_data.distro.lower()
            d = distro_name_map.get(key)
            if d:
                resolved_distro_id = d.id
            elif key in distro_versions:
                versions = sorted(distro_versions[key])
                errors.append(
                    f"Multiple versions of '{sys_data.distro}' exist. "
                    f"Specify version: {', '.join(f'{sys_data.distro} {v}' for v in versions)}"
                )
            else:
                errors.append(f"Distribution '{sys_data.distro}' not found")
        elif resolved_distro_id is None:
            errors.append("Either 'distro' (name) or 'distro_id' is required")

        # Resolve group: name takes priority, fall back to ID
        resolved_group_id = sys_data.group_id
        if sys_data.group:
            g = group_name_map.get(sys_data.group.lower())
            if g:
                resolved_group_id = g.id
            else:
                errors.append(f"Group '{sys_data.group}' not found")
        elif resolved_group_id is None:
            errors.append("Either 'group' (name) or 'group_id' is required")

        # Resolve credential: name takes priority, fall back to ID
        resolved_cred_id = sys_data.credentials_id
        if sys_data.credential:
            c = cred_name_map.get(sys_data.credential.lower())
            if c:
                resolved_cred_id = c.id
            else:
                errors.append(f"Credential '{sys_data.credential}' not found")
        elif resolved_cred_id is None:
            errors.append("Either 'credential' (name) or 'credentials_id' is required")

        # Resolve tags: names take priority, fall back to IDs
        resolved_tag_ids = []
        if sys_data.tags:
            for tag_name in sys_data.tags:
                t = tag_name_map.get(tag_name.lower())
                if t:
                    resolved_tag_ids.append(t.id)
                else:
                    errors.append(f"Tag '{tag_name}' not found")
        elif sys_data.tag_ids:
            for tid in sys_data.tag_ids:
                if tid in all_tags_db:
                    resolved_tag_ids.append(tid)
                else:
                    errors.append(f"Tag ID {tid} not found")

        # Validate hostname format
        if not sys_data.hostname or not HOSTNAME_PATTERN.match(sys_data.hostname):
            errors.append("Invalid hostname format")

        # Validate status
        if sys_data.status not in VALID_STATUSES:
            errors.append(
                f"Invalid status. Must be one of: {', '.join(VALID_STATUSES)}"
            )

        # Validate environment
        if sys_data.environment and sys_data.environment not in VALID_ENVIRONMENTS:
            errors.append(
                f"Invalid environment. Must be one of: {', '.join(VALID_ENVIRONMENTS)}"
            )

        # Check for duplicate hostname
        if sys_data.hostname in existing_hostnames:
            errors.append(f"System with hostname '{sys_data.hostname}' already exists")
        elif sys_data.hostname in batch_hostnames:
            errors.append(
                f"Duplicate hostname '{sys_data.hostname}' within import batch"
            )

        # Check for duplicate IP
        if sys_data.ip_address in existing_ips:
            errors.append(
                f"System with IP address '{sys_data.ip_address}' already exists"
            )
        elif sys_data.ip_address in batch_ips:
            errors.append(
                f"Duplicate IP address '{sys_data.ip_address}' within import batch"
            )

        # Validate resolved foreign keys exist
        if resolved_distro_id and resolved_distro_id not in all_distros:
            errors.append(f"Distribution with ID {resolved_distro_id} not found")

        if resolved_group_id and resolved_group_id not in all_groups:
            errors.append(f"Group with ID {resolved_group_id} not found")

        if resolved_cred_id and resolved_cred_id not in all_credentials:
            errors.append(f"Credential with ID {resolved_cred_id} not found")

        if errors:
            results.append(
                {
                    "hostname": sys_data.hostname,
                    "status": "error",
                    "message": "; ".join(errors),
                }
            )
        else:
            results.append(
                {
                    "hostname": sys_data.hostname,
                    "status": "validated" if payload.dry_run else "created",
                    "message": (
                        "Validation passed"
                        if payload.dry_run
                        else "System created successfully"
                    ),
                }
            )
            # Store resolved IDs alongside original data
            systems_to_create.append(
                {
                    "data": sys_data,
                    "distro_id": resolved_distro_id,
                    "group_id": resolved_group_id,
                    "credentials_id": resolved_cred_id,
                    "tag_ids": resolved_tag_ids,
                }
            )
            batch_hostnames.add(sys_data.hostname)
            batch_ips.add(sys_data.ip_address)

    # If dry run, return validation results only
    if payload.dry_run:
        created_count = sum(1 for r in results if r["status"] == "validated")
        return {
            "dry_run": True,
            "total": len(payload.systems),
            "valid": created_count,
            "errors": len(payload.systems) - created_count,
            "results": results,
        }

    fleet_op_id = fleet_operation_service.start_operation(
        operation_type="bulk_import",
        user_id=current_user.id,
        target_count=len(payload.systems),
        parameters={"count": len(payload.systems)},
    )

    # Record validation failures up front
    for r in results:
        if r["status"] == "error":
            fleet_operation_service.record_result(
                fleet_op_id, None, "failure", r["message"]
            )

    # Create valid systems
    for resolved in systems_to_create:
        sys_data = resolved["data"]
        r_distro_id = resolved["distro_id"]
        r_group_id = resolved["group_id"]
        r_cred_id = resolved["credentials_id"]
        r_tag_ids = resolved["tag_ids"]

        distro = all_distros[r_distro_id]

        db_system = System(
            hostname=sys_data.hostname,
            ip_address=sys_data.ip_address,
            distro_id=r_distro_id,
            os_version=distro.version,
            status=sys_data.status,
            group_id=r_group_id,
            credentials_id=r_cred_id,
            registered_at=datetime.utcnow(),
            registered_by=current_user.id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )

        db.add(db_system)
        db.flush()

        # Create system metadata
        metadata = SystemMetadata(
            system_id=db_system.id,
            environment_type=sys_data.environment or "Production",
            owner_contact=current_user.email,
            ssh_port=22,
            connection_status="Pending",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(metadata)

        # Assign tags if provided
        if r_tag_ids:
            for tag_id in r_tag_ids:
                db.execute(
                    system_tag.insert().values(
                        system_id=db_system.id,
                        tag_id=tag_id,
                        created_at=datetime.utcnow(),
                    )
                )

        record_audit(
            db,
            system_id=db_system.id,
            user_id=current_user.id,
            operation="bulk_import",
            audit_type="system",
            old_value=None,
            new_value=snapshot_system(db_system),
        )

        fleet_operation_service.record_result(fleet_op_id, db_system.id, "success")

    db.commit()

    created_count = sum(1 for r in results if r["status"] == "created")
    error_count = len(payload.systems) - created_count
    fleet_operation_service.complete_operation(fleet_op_id, created_count, error_count)

    # Notification: bulk operation complete (PRA-99)
    create_notification(
        db,
        type="bulk_operation_complete",
        title="Bulk import complete",
        message=f"Imported {created_count} systems, {error_count} errors",
        severity="info" if error_count == 0 else "warning",
    )

    return {
        "dry_run": False,
        "total": len(payload.systems),
        "created": created_count,
        "errors": error_count,
        "results": results,
        "fleet_operation_id": fleet_op_id,
    }


@router.get("/import/template")
def get_import_template(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Return the expected JSON schema for bulk system import,
    including available distros, groups, credentials, and tags.
    """
    # PRA-281: the template enumerates every credential name + type (secret
    # inventory) alongside distros/groups/tags, and it exists only to drive the
    # tenant-wide-admin-only import flow. Rather than trim the credential list for
    # scoped callers, keep it consistent with import: tenant-wide-admin-only.
    _require_tenant_wide_admin(
        db, current_user, "Bulk import template requires tenant-wide admin access"
    )

    distros = [
        {"id": d.id, "name": d.name, "version": d.version}
        for d in db.query(Distro).all()
    ]
    groups = [{"id": g.id, "name": g.name} for g in db.query(Group).all()]
    credentials = [
        {"id": c.id, "name": c.name, "type": c.auth_method}
        for c in db.query(Credential).all()
    ]
    tags = [{"id": t.id, "name": t.name} for t in db.query(Tag).all()]

    return {
        "description": "Bulk system import template — use names or IDs",
        "example": {
            "systems": [
                {
                    "hostname": "server-01.example.com",
                    "ip_address": "192.168.1.100",
                    "distro": "Ubuntu",
                    "group": "All Systems",
                    "credential": "default",
                    "status": "Active",
                    "environment": "Production",
                    "tags": ["web-server", "production"],
                }
            ],
            "dry_run": False,
        },
        "field_descriptions": {
            "hostname": "RFC 1123 compliant hostname (required)",
            "ip_address": "IPv4 or IPv6 address (required, must be unique)",
            "distro / distro_id": "Distribution name or ID (one required)",
            "group / group_id": "Group name or ID (one required)",
            "credential / credentials_id": "Credential name or ID (one required)",
            "status": "Active | Inactive | Maintenance | Decommissioned (defaults to Active)",
            "environment": "Production | Staging | Development | Testing (defaults to Production)",
            "tags / tag_ids": "List of tag names or IDs to assign (optional)",
        },
        "available_values": {
            "distros": distros,
            "groups": groups,
            "credentials": credentials,
            "tags": tags,
        },
    }
