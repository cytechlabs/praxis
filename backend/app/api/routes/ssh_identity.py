"""
API routes for SSH identity (zero-trust Vault CA) management (PRA-44).
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from pydantic import BaseModel, validator
from sqlalchemy.orm import Session

from ...core.auth import require_role, require_system_access
from ...db.models import SSHIdentitySettings, System, User
from ...db.session import get_db
from ...services import ca_rotation_service
from ...services.access_authorization_service import (
    scope_query_by_system,
    scoped_system_ids,
    user_can_access_system,
)
from ...services.ssh_identity_service import SSHIdentityError, SSHIdentityService
from ...services.vault_service import (
    VaultConnectionError,
    VaultSecretError,
    VaultService,
)

router = APIRouter(redirect_slashes=False)


def _emit_ca_audit(
    db: Session, request: Request, user: User, action: str, outcome: str = "success"
) -> None:
    """Emit a unified AuditEvent for an SSH CA lifecycle action (PRA-219).

    Complements the durable ``CARotation`` history row so CA rotate/revoke also
    reach external audit sinks. No key material is included in context.
    """
    from ...services.audit_event_service import safe_emit

    safe_emit(
        db=db,
        action=action,
        outcome=outcome,
        actor_user_id=user.id,
        actor_username=user.username,
        actor_ip=request.client.host if request and request.client else None,
        target_kind="ssh_ca",
        context={},
    )


class SSHIdentitySettingsResponse(BaseModel):
    user_cert_ttl_seconds: int
    default_principal: Optional[str]
    ca_identifier: Optional[str]
    ca_public_key: Optional[str] = None

    class Config:
        from_attributes = True


class SSHIdentitySettingsUpdate(BaseModel):
    user_cert_ttl_seconds: int
    default_principal: Optional[str] = None

    @validator("user_cert_ttl_seconds")
    def validate_ttl(cls, v):
        if not 60 <= v <= 3600:
            raise ValueError("TTL must be between 60 and 3600 seconds")
        return v


class BulkDeployIn(BaseModel):
    system_ids: List[int]


def _get_settings(db: Session) -> SSHIdentitySettings:
    settings = db.query(SSHIdentitySettings).first()
    if not settings:
        settings = SSHIdentitySettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


@router.get("/settings", response_model=SSHIdentitySettingsResponse)
def get_settings(
    current_user: User = Depends(require_role("admin")),  # noqa: ARG001
    db: Session = Depends(get_db),
):
    """Return SSH identity settings plus the Vault CA public key."""
    settings = _get_settings(db)
    ca_pubkey = None
    try:
        ca_pubkey = VaultService(db).get_ssh_ca_public_key()
    except (VaultConnectionError, VaultSecretError):
        ca_pubkey = None
    return {
        "user_cert_ttl_seconds": settings.user_cert_ttl_seconds,
        "default_principal": settings.default_principal,
        "ca_identifier": settings.ca_identifier,
        "ca_public_key": ca_pubkey,
    }


@router.put("/settings", response_model=SSHIdentitySettingsResponse)
def update_settings(
    payload: SSHIdentitySettingsUpdate,
    current_user: User = Depends(require_role("admin")),  # noqa: ARG001
    db: Session = Depends(get_db),
):
    """Update SSH identity settings."""
    settings = _get_settings(db)
    settings.user_cert_ttl_seconds = payload.user_cert_ttl_seconds
    settings.default_principal = payload.default_principal
    db.commit()
    db.refresh(settings)
    ca_pubkey = None
    try:
        ca_pubkey = VaultService(db).get_ssh_ca_public_key()
    except (VaultConnectionError, VaultSecretError):
        ca_pubkey = None
    return {
        "user_cert_ttl_seconds": settings.user_cert_ttl_seconds,
        "default_principal": settings.default_principal,
        "ca_identifier": settings.ca_identifier,
        "ca_public_key": ca_pubkey,
    }


@router.get("/status", response_model=Dict[str, Any])
def fleet_status(
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Return fleet zero-trust deployment counts."""
    # PRA-281: scope the fleet counts (None = tenant-wide admin; empty scope → 0).
    total = scope_query_by_system(db.query(System), db, current_user, System.id).count()
    deployed = scope_query_by_system(
        db.query(System).filter(System.ca_trust_deployed.is_(True)),
        db,
        current_user,
        System.id,
    ).count()
    return {
        "total_systems": total,
        "deployed": deployed,
        "percent": (deployed * 100 / total) if total else 0,
    }


@router.post(
    "/deploy/{system_id}",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access("admin"))],
)
def deploy_ca_trust(
    system_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),  # noqa: ARG001
    db: Session = Depends(get_db),
):
    """Deploy the Vault CA public key to a system."""
    try:
        return SSHIdentityService(db).deploy_ca_trust(system_id)
    except SSHIdentityError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.delete(
    "/revoke/{system_id}",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access("admin"))],
)
def revoke_ca_trust(
    system_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),  # noqa: ARG001
    db: Session = Depends(get_db),
):
    """Revoke (remove) CA trust from a system."""
    try:
        return SSHIdentityService(db).revoke_ca_trust(system_id)
    except SSHIdentityError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/rotate-ca", response_model=Dict[str, Any])
def rotate_ca(
    request: Request,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Regenerate the Vault SSH CA and flag every system for redeploy (PRA-128)."""
    try:
        result = ca_rotation_service.rotate_ca(db, performed_by=current_user.id)
    except (VaultConnectionError, VaultSecretError) as e:
        raise HTTPException(status_code=500, detail=f"Vault error: {e}") from e
    # PRA-219: emit a unified AuditEvent for the CA rotation (in addition to the
    # CARotation history row). No private key material is included.
    _emit_ca_audit(db, request, current_user, "ssh.ca.rotate")
    return result


@router.post("/revoke-user-certs", response_model=Dict[str, Any])
def revoke_user_certs(
    request: Request,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Bump ca_identifier + drop pooled SSH sessions (PRA-128)."""
    result = ca_rotation_service.revoke_user_certs(db, performed_by=current_user.id)
    _emit_ca_audit(db, request, current_user, "ssh.ca.revoke_user_certs")
    return result


@router.get("/rotations", response_model=Dict[str, Any])
def list_rotations(
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Return CA rotation/revocation history."""
    return {"rotations": ca_rotation_service.list_rotations(db)}


@router.post(
    "/systems/{system_id}/enroll-access-broker",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access("admin"))],
)
def enroll_access_broker(
    system_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),  # noqa: ARG001
    db: Session = Depends(get_db),
):
    """Full PRA-138 enrollment: CA trust + principals hook + self-test."""
    try:
        return SSHIdentityService(db).enroll_access_broker(system_id)
    except SSHIdentityError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post(
    "/systems/{system_id}/deploy-principals-hook",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access("admin"))],
)
def deploy_principals_hook(
    system_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),  # noqa: ARG001
    db: Session = Depends(get_db),
):
    """Install the AuthorizedPrincipalsCommand wrapper only (CA trust must already be deployed)."""
    try:
        return SSHIdentityService(db).deploy_principals_hook(system_id)
    except SSHIdentityError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post(
    "/systems/{system_id}/revoke-principals-hook",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access("admin"))],
)
def revoke_principals_hook(
    system_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),  # noqa: ARG001
    db: Session = Depends(get_db),
):
    """Remove the PRA-138 sshd directives + praxis-principals script."""
    try:
        return SSHIdentityService(db).revoke_principals_hook(system_id)
    except SSHIdentityError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post(
    "/systems/{system_id}/self-test",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access("admin"))],
)
def self_test(
    system_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),  # noqa: ARG001
    db: Session = Depends(get_db),
):
    """Attempt cert-auth against the host and run a trivial remote command."""
    try:
        return SSHIdentityService(db).self_test_cert_auth(system_id)
    except SSHIdentityError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post(
    "/systems/{system_id}/check-allowlist",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access("admin"))],
)
def check_access_allowlist(
    system_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),  # noqa: ARG001
    db: Session = Depends(get_db),
):
    """Check native sshd allow-list compatibility for provisioned logins (PRA-234).

    Reads effective sshd ``AllowUsers`` / ``AllowGroups`` / ``DenyUsers`` /
    ``DenyGroups`` policy over a bootstrap connection and reports which
    provisioned logins would be rejected at the account gate — even when CA
    trust and the principals hook are healthy. Read-only; never edits host
    policy.
    """
    try:
        return SSHIdentityService(db).check_access_allowlist(system_id)
    except SSHIdentityError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/deploy-bulk", response_model=Dict[str, Any])
def deploy_bulk(
    payload: BulkDeployIn,
    current_user: User = Depends(require_role("admin")),  # noqa: ARG001
    db: Session = Depends(get_db),
):
    """Deploy CA trust to a list of systems. Returns per-system results."""
    # PRA-281: reject the whole request with a non-disclosing 404 if ANY requested
    # system is out of scope — never partially deploy a mixed batch. Admins
    # (tenant-wide) pass. Checked before any per-system deploy runs.
    scope = scoped_system_ids(db, current_user)
    if scope is not None:
        for sid in payload.system_ids:
            if not user_can_access_system(db, current_user, sid):
                raise HTTPException(status_code=404, detail="System not found")
    service = SSHIdentityService(db)
    results = []
    for sid in payload.system_ids:
        try:
            result = service.deploy_ca_trust(sid)
            results.append({**result, "system_id": sid, "success": True})
        except SSHIdentityError as e:
            results.append({"system_id": sid, "success": False, "error": str(e)})
    success_count = sum(1 for r in results if r["success"])
    return {
        "total": len(results),
        "success": success_count,
        "failed": len(results) - success_count,
        "results": results,
    }
