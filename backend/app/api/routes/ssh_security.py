"""
API routes for SSH security management.
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role
from ...db.models import System, User
from ...db.session import get_db
from ...db.ssh_security_models import SSHHostKey, SSHSecurityLog, SSHSecurityPolicy
from ...services.access_authorization_service import scoped_system_ids
from ..schemas.ssh_security import SSHHostKey as SSHHostKeySchema
from ..schemas.ssh_security import SSHHostKeyList, SSHHostKeyUpdate
from ..schemas.ssh_security import SSHSecurityLog as SSHSecurityLogSchema
from ..schemas.ssh_security import SSHSecurityLogList
from ..schemas.ssh_security import SSHSecurityPolicy as SSHSecurityPolicySchema
from ..schemas.ssh_security import (
    SSHSecurityPolicyCreate,
    SSHSecurityPolicyList,
    SSHSecurityPolicyUpdate,
)

router = APIRouter()


def _scope_or_404(db: Session, current_user: User, system_id: Optional[int]):
    """PRA-281: resolve fleet scope; a scoped caller supplying an out-of-scope
    ``system_id`` filter gets a non-disclosing 404 before any query. Returns the
    scope set (``None`` = tenant-wide admin) for threading into row filters."""
    scope = scoped_system_ids(db, current_user)
    if system_id is not None and scope is not None and system_id not in scope:
        raise HTTPException(status_code=404, detail=f"System {system_id} not found")
    return scope


def _apply_scope(query, column, scope):
    """Filter a host-derived query to the caller's fleet scope (admin None →
    unchanged; empty scope → no rows)."""
    if scope is None:
        return query
    if not scope:
        from sqlalchemy import false

        return query.filter(false())
    return query.filter(column.in_(scope))


def _enforce_row_scope(row_system_id, scope) -> None:
    """Non-disclosing 404 for a direct host-derived row outside fleet scope."""
    if scope is not None and row_system_id not in scope:
        raise HTTPException(status_code=404, detail="not found")


@router.get("/policies", response_model=SSHSecurityPolicyList)
def get_ssh_security_policies(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Number of records to return"),
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
):
    """Get all SSH security policies."""
    policies = db.query(SSHSecurityPolicy).offset(skip).limit(limit).all()
    total = db.query(SSHSecurityPolicy).count()

    return SSHSecurityPolicyList(policies=policies, total=total)


@router.get("/policies/{policy_id}", response_model=SSHSecurityPolicySchema)
def get_ssh_security_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
):
    """Get a specific SSH security policy."""
    policy = (
        db.query(SSHSecurityPolicy).filter(SSHSecurityPolicy.id == policy_id).first()
    )
    if not policy:
        raise HTTPException(status_code=404, detail="SSH security policy not found")

    return policy


@router.post("/policies", response_model=SSHSecurityPolicySchema)
def create_ssh_security_policy(
    policy_data: SSHSecurityPolicyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "maintainer")),
):
    """Create a new SSH security policy."""
    # Check if policy name already exists
    existing_policy = (
        db.query(SSHSecurityPolicy)
        .filter(SSHSecurityPolicy.name == policy_data.name)
        .first()
    )
    if existing_policy:
        raise HTTPException(status_code=400, detail="Policy name already exists")

    policy = SSHSecurityPolicy(
        **policy_data.dict(),
        created_by=current_user.id,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )

    db.add(policy)
    db.commit()
    db.refresh(policy)

    return policy


@router.put("/policies/{policy_id}", response_model=SSHSecurityPolicySchema)
def update_ssh_security_policy(
    policy_id: int,
    policy_data: SSHSecurityPolicyUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "maintainer")),
):
    """Update an SSH security policy."""
    policy = (
        db.query(SSHSecurityPolicy).filter(SSHSecurityPolicy.id == policy_id).first()
    )
    if not policy:
        raise HTTPException(status_code=404, detail="SSH security policy not found")

    # Check if new name already exists (if name is being updated)
    if policy_data.name and policy_data.name != policy.name:
        existing_policy = (
            db.query(SSHSecurityPolicy)
            .filter(SSHSecurityPolicy.name == policy_data.name)
            .first()
        )
        if existing_policy:
            raise HTTPException(status_code=400, detail="Policy name already exists")

    # Update fields
    update_data = policy_data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(policy, field, value)

    policy.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(policy)

    return policy


@router.delete("/policies/{policy_id}")
def delete_ssh_security_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_role("admin", "maintainer")),
):
    """Delete an SSH security policy."""
    policy = (
        db.query(SSHSecurityPolicy).filter(SSHSecurityPolicy.id == policy_id).first()
    )
    if not policy:
        raise HTTPException(status_code=404, detail="SSH security policy not found")

    # Check if policy is in use by any systems
    systems_using_policy = (
        db.query(System).filter(System.ssh_security_policy_id == policy_id).count()
    )
    if systems_using_policy > 0:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete policy. It is currently used by {systems_using_policy} system(s)",
        )

    db.delete(policy)
    db.commit()

    return {"message": "SSH security policy deleted successfully"}


@router.get("/logs", response_model=SSHSecurityLogList)
def get_ssh_security_logs(
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Number of records to return"),
    system_id: Optional[int] = Query(None, description="Filter by system ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    success: Optional[bool] = Query(None, description="Filter by success status"),
):
    """Get SSH security logs with optional filtering."""
    # PRA-281: out-of-scope system_id filter → 404 before query; else fleet-scope.
    scope = _scope_or_404(db, _current_user, system_id)
    query = _apply_scope(db.query(SSHSecurityLog), SSHSecurityLog.system_id, scope)

    if system_id:
        query = query.filter(SSHSecurityLog.system_id == system_id)
    if event_type:
        query = query.filter(SSHSecurityLog.event_type == event_type)
    if success is not None:
        query = query.filter(SSHSecurityLog.success == success)

    # Order by timestamp descending (newest first)
    query = query.order_by(SSHSecurityLog.timestamp.desc())

    logs = query.offset(skip).limit(limit).all()
    total = query.count()

    return SSHSecurityLogList(logs=logs, total=total)


@router.get("/logs/{log_id}", response_model=SSHSecurityLogSchema)
def get_ssh_security_log(
    log_id: int,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
):
    """Get a specific SSH security log entry."""
    log = db.query(SSHSecurityLog).filter(SSHSecurityLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="SSH security log not found")
    _enforce_row_scope(log.system_id, scoped_system_ids(db, _current_user))

    return log


@router.get("/host-keys", response_model=SSHHostKeyList)
def get_ssh_host_keys(
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Number of records to return"),
    system_id: Optional[int] = Query(None, description="Filter by system ID"),
    verified: Optional[bool] = Query(None, description="Filter by verification status"),
):
    """Get SSH host keys with optional filtering."""
    scope = _scope_or_404(db, _current_user, system_id)
    query = _apply_scope(db.query(SSHHostKey), SSHHostKey.system_id, scope)

    if system_id:
        query = query.filter(SSHHostKey.system_id == system_id)
    if verified is not None:
        query = query.filter(SSHHostKey.verified == verified)

    # Order by last seen descending (most recent first)
    query = query.order_by(SSHHostKey.last_seen.desc())

    host_keys = query.offset(skip).limit(limit).all()
    total = query.count()

    return SSHHostKeyList(host_keys=host_keys, total=total)


# NOTE: the static ``/host-keys/unverified`` route is declared BEFORE the dynamic
# ``/host-keys/{host_key_id}`` route so FastAPI matches the literal segment first
# (feedback_fastapi_route_ordering.md); otherwise "unverified" is parsed as an int
# host_key_id and the endpoint is unreachable.
@router.get("/host-keys/unverified", response_model=SSHHostKeyList)
def get_unverified_host_keys(
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Number of records to return"),
):
    """Get all unverified SSH host keys that need manual verification."""
    query = db.query(SSHHostKey).filter(SSHHostKey.verified.is_(False))
    query = _apply_scope(
        query, SSHHostKey.system_id, scoped_system_ids(db, _current_user)
    )

    # Order by last seen descending (most recent first)
    query = query.order_by(SSHHostKey.last_seen.desc())

    host_keys = query.offset(skip).limit(limit).all()
    total = query.count()

    return SSHHostKeyList(host_keys=host_keys, total=total)


@router.get("/host-keys/{host_key_id}", response_model=SSHHostKeySchema)
def get_ssh_host_key(
    host_key_id: int,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
):
    """Get a specific SSH host key."""
    host_key = db.query(SSHHostKey).filter(SSHHostKey.id == host_key_id).first()
    if not host_key:
        raise HTTPException(status_code=404, detail="SSH host key not found")
    # PRA-281: non-disclosing 404 before any read/mutation or hostname-bearing
    # success message for a host key outside the caller's fleet scope.
    _enforce_row_scope(host_key.system_id, scoped_system_ids(db, _current_user))

    return host_key


@router.put("/host-keys/{host_key_id}", response_model=SSHHostKeySchema)
def update_ssh_host_key(
    host_key_id: int,
    host_key_data: SSHHostKeyUpdate,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_role("admin", "maintainer")),
):
    """Update an SSH host key (mainly for verification status)."""
    host_key = db.query(SSHHostKey).filter(SSHHostKey.id == host_key_id).first()
    if not host_key:
        raise HTTPException(status_code=404, detail="SSH host key not found")
    # PRA-281: non-disclosing 404 before any read/mutation or hostname-bearing
    # success message for a host key outside the caller's fleet scope.
    _enforce_row_scope(host_key.system_id, scoped_system_ids(db, _current_user))

    # Update fields
    update_data = host_key_data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(host_key, field, value)

    host_key.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(host_key)

    return host_key


@router.delete("/host-keys/{host_key_id}")
def delete_ssh_host_key(
    host_key_id: int,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_role("admin", "maintainer")),
):
    """Delete an SSH host key."""
    host_key = db.query(SSHHostKey).filter(SSHHostKey.id == host_key_id).first()
    if not host_key:
        raise HTTPException(status_code=404, detail="SSH host key not found")
    # PRA-281: non-disclosing 404 before any read/mutation or hostname-bearing
    # success message for a host key outside the caller's fleet scope.
    _enforce_row_scope(host_key.system_id, scoped_system_ids(db, _current_user))

    db.delete(host_key)
    db.commit()

    return {"message": "SSH host key deleted successfully"}


@router.post("/host-keys/{host_key_id}/verify")
def verify_ssh_host_key(
    host_key_id: int,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_role("admin", "maintainer")),
):
    """Verify an SSH host key (mark as trusted)."""
    host_key = db.query(SSHHostKey).filter(SSHHostKey.id == host_key_id).first()
    if not host_key:
        raise HTTPException(status_code=404, detail="SSH host key not found")
    # PRA-281: non-disclosing 404 before any read/mutation or hostname-bearing
    # success message for a host key outside the caller's fleet scope.
    _enforce_row_scope(host_key.system_id, scoped_system_ids(db, _current_user))

    host_key.verified = True
    host_key.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(host_key)

    return {
        "message": f"Host key for {host_key.hostname} has been verified and marked as trusted",
        "host_key": host_key,
    }


@router.post("/host-keys/{host_key_id}/unverify")
def unverify_ssh_host_key(
    host_key_id: int,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_role("admin", "maintainer")),
):
    """Unverify an SSH host key (mark as untrusted)."""
    host_key = db.query(SSHHostKey).filter(SSHHostKey.id == host_key_id).first()
    if not host_key:
        raise HTTPException(status_code=404, detail="SSH host key not found")
    # PRA-281: non-disclosing 404 before any read/mutation or hostname-bearing
    # success message for a host key outside the caller's fleet scope.
    _enforce_row_scope(host_key.system_id, scoped_system_ids(db, _current_user))

    host_key.verified = False
    host_key.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(host_key)

    return {
        "message": f"Host key for {host_key.hostname} has been marked as unverified",
        "host_key": host_key,
    }


@router.get("/event-types")
def get_ssh_security_event_types(
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
):
    """Get all available SSH security event types."""
    # PRA-281: only event types occurring on in-scope systems (empty scope → []).
    query = _apply_scope(
        db.query(SSHSecurityLog.event_type),
        SSHSecurityLog.system_id,
        scoped_system_ids(db, _current_user),
    )
    event_types = query.distinct().all()
    return {"event_types": [event_type[0] for event_type in event_types]}
