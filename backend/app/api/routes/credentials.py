"""
Credential management routes module.

All secrets are stored in Vault. DB stores metadata only.
"""

import logging
import re
from typing import Any, Dict, List

from fastapi import (  # pylint:disable=wrong-import-order
    APIRouter,
    Depends,
    HTTPException,
    Request,
    status,
)
from sqlalchemy import text  # pylint:disable=wrong-import-order
from sqlalchemy.orm import Session  # pylint:disable=wrong-import-order

from app.api.schemas.credentials import (
    CredentialCreate,
    CredentialResponse,
    CredentialUpdate,
)
from app.core.auth import get_current_user, require_role
from app.db.models import Credential, System, User
from app.db.session import get_db
from app.services.access_authorization_service import scoped_system_ids
from app.services.notification_service import create_notification
from app.services.vault_service import VaultConnectionError, VaultService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["credentials"])


def _credential_visible_to_scope(credential: Credential, scope) -> bool:
    """PRA-281: a credential is host-derived through the systems it is linked to.

    Admin (scope ``None``) sees all. A scoped caller may see/reveal/mutate a
    credential only when it is linked to at least one system AND EVERY linked
    system is in scope. This fails closed for:
      * mixed usage (some linked systems out of scope) — returning a partial
        ``systems`` list would leak that other, hidden hosts share the secret;
      * unattached credentials (no linked systems) — tenant-wide secret inventory
        that a scoped caller has no host-derived claim on.
    """
    if scope is None:
        return True
    linked = {s.id for s in credential.systems}
    return bool(linked) and linked.issubset(scope)


def _generate_vault_path(name: str) -> str:
    """Generate a Vault path from a credential name."""
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "-", name.lower()).strip("-")
    return f"praxis/credentials/{safe_name}"


def _emit_credential_audit(
    db: Session,
    request: Request,
    user: User,
    action: str,
    *,
    credential_id: int,
    context: Dict[str, Any],
    outcome: str = "success",
) -> None:
    """Emit a unified AuditEvent for a sensitive credential action (PRA-219).

    Routed through ``safe_emit`` so it persists to ``audit_events`` and fans out
    to external sinks. ``context`` must contain only non-secret locators/metadata
    (credential id/name/auth_method/vault_path) — never password, ssh_key,
    sudo_password, or any Vault secret value.
    """
    from app.services.audit_event_service import safe_emit

    safe_emit(
        db=db,
        action=action,
        outcome=outcome,
        actor_user_id=user.id,
        actor_username=user.username,
        actor_ip=request.client.host if request and request.client else None,
        target_kind="credential",
        target_id=str(credential_id),
        context=context,
    )


def credential_to_response(credential: Credential) -> dict:
    """Convert Credential model to response dict with systems."""
    return {
        "id": credential.id,
        "name": credential.name,
        "auth_method": credential.auth_method,
        "username": credential.username,
        "vault_path": credential.vault_path,
        "sudo_method": credential.sudo_method,
        "systems": [
            {
                "id": system.id,
                "hostname": system.hostname,
                "ip_address": str(system.ip_address),
            }
            for system in credential.systems
        ],
        "created_at": credential.created_at,
        "updated_at": credential.updated_at,
    }


@router.get("", response_model=List[CredentialResponse])
async def get_credentials(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint:disable=unused-argument
) -> Any:
    """Get all credentials (metadata only, no secrets)."""
    credentials = db.query(Credential).all()
    scope = scoped_system_ids(db, current_user)
    if scope is not None:
        credentials = [c for c in credentials if _credential_visible_to_scope(c, scope)]
    return [credential_to_response(credential) for credential in credentials]


@router.get("/{credential_id}", response_model=CredentialResponse)
async def get_credential(
    credential_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint:disable=unused-argument
) -> Any:
    """Get a specific credential by ID (metadata only, no secrets)."""
    credential = db.query(Credential).filter(Credential.id == credential_id).first()
    if not credential:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential with ID {credential_id} not found",
        )
    # PRA-281: non-disclosing 404 for a credential not fully within the caller's
    # fleet scope — BEFORE any Vault read/write/delete, notification, audit, DB
    # mutation, or hostname-bearing error message.
    if not _credential_visible_to_scope(
        credential, scoped_system_ids(db, current_user)
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential with ID {credential_id} not found",
        )
    return credential_to_response(credential)


@router.get("/{credential_id}/secret", response_model=Dict[str, Any])
async def reveal_credential_secret(
    credential_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "maintainer")),
) -> Any:
    """Reveal the secret data for a credential from Vault.

    Requires admin or maintainer role. Access is audit-logged.
    """
    credential = db.query(Credential).filter(Credential.id == credential_id).first()
    if not credential:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential with ID {credential_id} not found",
        )
    # PRA-281: non-disclosing 404 for a credential not fully within the caller's
    # fleet scope — BEFORE any Vault read/write/delete, notification, audit, DB
    # mutation, or hostname-bearing error message.
    if not _credential_visible_to_scope(
        credential, scoped_system_ids(db, current_user)
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential with ID {credential_id} not found",
        )

    if not credential.vault_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credential has no Vault path configured",
        )

    try:
        vault_service = VaultService(db)
        secret_data = vault_service.read_secret(credential.vault_path)
        if secret_data is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Secret not found in Vault",
            )

        # Audit log the reveal: keep the in-app notification AND emit a unified
        # AuditEvent (PRA-219) so secret access reaches external sinks. Context
        # carries metadata only — never the revealed secret_data.
        create_notification(
            db,
            type="security",
            title=f"Credential secret revealed: {credential.name}",
            message=f"User '{current_user.username}' revealed secret for credential '{credential.name}'",
            severity="warning",
        )
        _emit_credential_audit(
            db,
            request,
            current_user,
            "credential.secret.reveal",
            credential_id=credential.id,
            context={
                "name": credential.name,
                "auth_method": credential.auth_method,
                "vault_path": credential.vault_path,
            },
        )

        return {"credential_id": credential_id, "data": secret_data}
    except VaultConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Vault unavailable: {str(e)}",
        ) from e


@router.post("", response_model=CredentialResponse, status_code=status.HTTP_201_CREATED)
async def create_credential(
    credential_data: CredentialCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Create a new credential. Secrets are stored in Vault."""
    # PRA-281: credential creation is global secret inventory (a new credential is
    # unattached, so it has no host-derived scope) and, in linked mode, reads an
    # operator-supplied Vault path. Restrict it to tenant-wide admins BEFORE the
    # duplicate-name check or ANY Vault read/write — otherwise a scoped maintainer
    # could enumerate hidden credential names via duplicate-name errors or probe
    # arbitrary Vault paths / key shapes in linked mode.
    if scoped_system_ids(db, current_user) is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Creating credentials requires tenant-wide admin access",
        )
    # Check if credential with same name already exists
    existing_credential = (
        db.query(Credential).filter(Credential.name == credential_data.name).first()
    )
    if existing_credential:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Credential with name '{credential_data.name}' already exists",
        )

    # Determine vault path
    vault_path = credential_data.vault_path or _generate_vault_path(
        credential_data.name
    )

    # "Linked" mode: user supplied vault_path pointing at an existing secret and
    # no inline secrets — verify the secret exists and pull username from it if
    # the caller didn't provide one. Otherwise this is "managed" mode and we
    # write the secret to Vault from the request body.
    is_linked_mode = bool(credential_data.vault_path) and not any(
        [
            credential_data.password,
            credential_data.ssh_key,
            credential_data.sudo_password,
        ]
    )

    username = credential_data.username

    try:
        vault_service = VaultService(db)

        if is_linked_mode:
            existing_secret = vault_service.read_secret(vault_path)
            if not existing_secret:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"Vault secret not found at '{vault_path}'. Create the "
                        "secret first or provide inline credentials."
                    ),
                )
            secret_payload = existing_secret or {}
            required_key = (
                "password" if credential_data.auth_method == "password" else "ssh_key"
            )
            if not secret_payload.get(required_key):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"Vault secret at '{vault_path}' is missing the "
                        f"'{required_key}' key required for auth_method "
                        f"'{credential_data.auth_method}'."
                    ),
                )
            if not username:
                username = secret_payload.get("username")
        else:
            secret_data = {}
            if credential_data.auth_method == "password":
                secret_data["password"] = credential_data.password
            elif credential_data.auth_method == "ssh_key":
                secret_data["ssh_key"] = credential_data.ssh_key
            if credential_data.sudo_password:
                secret_data["sudo_password"] = credential_data.sudo_password

            if not vault_service.write_secret(vault_path, secret_data):
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to write secret to Vault",
                )
    except VaultConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Vault unavailable: {str(e)}",
        ) from e

    # Get the next ID value
    result = db.execute(text("SELECT COALESCE(MAX(id), 0) + 1 FROM credentials"))
    next_id = result.scalar()

    # Create metadata in DB
    credential = Credential(
        id=next_id,
        name=credential_data.name,
        auth_method=credential_data.auth_method,
        username=username,
        vault_path=vault_path,
        sudo_method=credential_data.sudo_method,
    )

    db.add(credential)
    db.commit()
    db.refresh(credential)

    create_notification(
        db,
        type="credential_change",
        title=f"Credential created: {credential.name}",
        message=f"New {credential.auth_method} credential '{credential.name}' added",
        severity="info",
    )
    _emit_credential_audit(
        db,
        request,
        current_user,
        "credential.create",
        credential_id=credential.id,
        context={
            "name": credential.name,
            "auth_method": credential.auth_method,
            "vault_path": vault_path,
            "mode": "linked" if is_linked_mode else "managed",
        },
    )

    return credential_to_response(credential)


@router.put("/{credential_id}", response_model=CredentialResponse)
async def update_credential(
    credential_id: int,
    credential_data: CredentialUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Update an existing credential. Secret updates are written to Vault."""
    credential = db.query(Credential).filter(Credential.id == credential_id).first()
    if not credential:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential with ID {credential_id} not found",
        )
    # PRA-281: non-disclosing 404 for a credential not fully within the caller's
    # fleet scope — BEFORE any Vault read/write/delete, notification, audit, DB
    # mutation, or hostname-bearing error message.
    if not _credential_visible_to_scope(
        credential, scoped_system_ids(db, current_user)
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential with ID {credential_id} not found",
        )

    # Check if name is being updated and if it already exists
    if credential_data.name and credential_data.name != credential.name:
        existing_credential = (
            db.query(Credential).filter(Credential.name == credential_data.name).first()
        )
        if existing_credential:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Credential with name '{credential_data.name}' already exists",
            )

    # If any secret fields are provided, update Vault
    has_secret_update = any(
        [
            credential_data.password,
            credential_data.ssh_key,
            credential_data.sudo_password,
        ]
    )
    if has_secret_update and credential.vault_path:
        try:
            vault_service = VaultService(db)
            # Read existing secret, merge updates
            existing_secret = vault_service.read_secret(credential.vault_path) or {}
            if credential_data.password:
                existing_secret["password"] = credential_data.password
            if credential_data.ssh_key:
                existing_secret["ssh_key"] = credential_data.ssh_key
            if credential_data.sudo_password:
                existing_secret["sudo_password"] = credential_data.sudo_password

            if not vault_service.write_secret(credential.vault_path, existing_secret):
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to update secret in Vault",
                )
        except VaultConnectionError as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Vault unavailable: {str(e)}",
            ) from e

    # Update DB metadata (exclude secret fields)
    metadata_fields = {"name", "auth_method", "username", "sudo_method"}
    update_data = credential_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        if key in metadata_fields:
            setattr(credential, key, value)

    db.commit()
    db.refresh(credential)

    create_notification(
        db,
        type="credential_change",
        title=f"Credential updated: {credential.name}",
        message=f"Credential '{credential.name}' was modified",
        severity="info",
    )
    _emit_credential_audit(
        db,
        request,
        current_user,
        "credential.update",
        credential_id=credential.id,
        context={
            "name": credential.name,
            "auth_method": credential.auth_method,
            "secret_updated": bool(has_secret_update),
        },
    )

    return credential_to_response(credential)


@router.delete("/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_credential(
    credential_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
):
    """Delete a credential. Removes secret from Vault and metadata from DB."""
    credential = db.query(Credential).filter(Credential.id == credential_id).first()
    if not credential:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential with ID {credential_id} not found",
        )
    # PRA-281: non-disclosing 404 for a credential not fully within the caller's
    # fleet scope — BEFORE any Vault read/write/delete, notification, audit, DB
    # mutation, or hostname-bearing error message.
    if not _credential_visible_to_scope(
        credential, scoped_system_ids(db, current_user)
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential with ID {credential_id} not found",
        )

    # Check if credential is being used by any systems
    systems_using_credential = (
        db.query(System).filter(System.credentials_id == credential_id).all()
    )
    if systems_using_credential:
        system_names = [system.hostname for system in systems_using_credential]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot delete credential as it is being used by systems: {', '.join(system_names)}",
        )

    # Delete from Vault
    if credential.vault_path:
        try:
            vault_service = VaultService(db)
            vault_service.delete_secret(credential.vault_path)
        except Exception:  # pylint: disable=broad-except
            logger.warning(
                "Failed to delete Vault secret for credential %s", credential.name
            )

    cred_name = credential.name
    cred_auth_method = credential.auth_method
    db.delete(credential)
    db.commit()

    create_notification(
        db,
        type="credential_change",
        title=f"Credential deleted: {cred_name}",
        message=f"Credential '{cred_name}' was removed",
        severity="info",
    )
    _emit_credential_audit(
        db,
        request,
        current_user,
        "credential.delete",
        credential_id=credential_id,
        context={"name": cred_name, "auth_method": cred_auth_method},
    )
