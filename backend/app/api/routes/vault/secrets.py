"""
Vault secrets management API routes.
"""

import logging
from typing import Dict, List  # pylint: disable=unused-import

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from ....core.auth import require_role
from ....db.models import User
from ....db.session import get_db
from ....services.vault_service import (
    VaultConnectionError,
    VaultSecretError,
    VaultService,
)
from ...schemas.vault.vault import (
    VaultKVStoresResponse,
    VaultSecretCreateRequest,
    VaultSecretDataResponse,
    VaultSecretPasswordUpdateRequest,
    VaultSecretsResponse,
    VaultSecretVersionResponse,
    VaultSecretVersionsResponse,
)

router = APIRouter()

logger = logging.getLogger(__name__)

# PRA-227 VAULT-01: Vault/transport failures are logged in full server-side but
# returned to API clients as bounded messages, so raw hvac/transport/stack
# detail never reaches even a privileged (admin/maintainer) caller.
_VAULT_UNAVAILABLE_DETAIL = (
    "Vault is currently unavailable. Verify the Vault connection and retry."
)


def _vault_unavailable(exc: Exception) -> HTTPException:
    """503 for a Vault connection failure, with the raw error kept server-side."""
    logger.error("Vault connection error: %s", exc)
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=_VAULT_UNAVAILABLE_DETAIL,
    )


def _vault_internal_error(exc: Exception, action: str) -> HTTPException:
    """500 for an unexpected Vault failure; the traceback is logged, not returned."""
    logger.exception("Vault error while trying to %s", action)
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=f"Failed to {action}.",
    )


def _emit_vault_secret_audit(
    db: Session,
    request: Request,
    user: User,
    action: str,
    path: str,
    outcome: str = "success",
    extra: dict = None,
) -> None:
    """Emit a unified AuditEvent for a direct Vault secret action (PRA-219).

    ``context`` carries only the Vault path (a locator, not a secret) plus
    bounded metadata. Secret values, passwords, and Vault exception detail are
    never placed in the event.
    """
    from ....services.audit_event_service import safe_emit

    context = {"vault_path": path}
    if extra:
        context.update(extra)
    safe_emit(
        db=db,
        action=action,
        outcome=outcome,
        actor_user_id=user.id,
        actor_username=user.username,
        actor_ip=request.client.host if request and request.client else None,
        target_kind="vault_secret",
        target_id=path,
        context=context,
    )


@router.get(
    "/kv-stores",
    response_model=VaultKVStoresResponse,
    summary="List all KV stores in Vault",
)
def list_kv_stores(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin", "maintainer")
    ),  # pylint: disable=unused-argument
):
    """
    List all KV stores in Vault.
    """
    vault_service = VaultService(db)
    try:
        # Get the KV stores from the service
        # The service now returns a hardcoded list based on the known structure
        # and returns an empty list instead of None on error
        kv_stores = vault_service.list_kv_stores()
        return {"kv_stores": kv_stores}
    except VaultConnectionError as e:
        raise _vault_unavailable(e) from e
    except HTTPException:
        raise
    except Exception as e:  # pylint: disable=broad-except
        raise _vault_internal_error(e, "list KV stores") from e


@router.get(
    "/secrets",
    response_model=VaultSecretsResponse,
    summary="List secrets in a KV store",
)
def list_secrets(
    path: str = Query(..., description="Path to the KV store"),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin", "maintainer")
    ),  # pylint: disable=unused-argument
):
    """
    List secrets in a KV store.
    """
    vault_service = VaultService(db)
    try:
        # The path parameter is the KV store name (e.g., "kv")
        # We pass it directly to the service which handles the specific path structure
        secrets = vault_service.list_secrets(path)

        # The service now returns an empty list instead of None on error
        # so we don't need to check for None anymore
        return {"secrets": secrets, "path": path}
    except VaultConnectionError as e:
        raise _vault_unavailable(e) from e
    except HTTPException:
        raise
    except Exception as e:  # pylint: disable=broad-except
        raise _vault_internal_error(e, "list secrets") from e


@router.get(
    "/secret",
    response_model=VaultSecretDataResponse,
    summary="Read a secret",
)
def read_secret(
    request: Request,
    path: str = Query(..., description="Path to the secret"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "maintainer")),
):
    """
    Read a secret from Vault.
    """
    vault_service = VaultService(db)
    try:
        data = vault_service.read_secret(path)
        if data is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Secret not found at path: {path}",
            )
        # Emit immediately after the successful secret-value read so the access
        # is always audited even if metadata lookup / response shaping fails.
        _emit_vault_secret_audit(db, request, current_user, "vault.secret.read", path)
        metadata = vault_service.read_secret_metadata(path)
        if metadata is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Secret not found at path: {path}",
            )
        return {"data": data, "metadata": metadata, "path": path}
    except VaultConnectionError as e:
        raise _vault_unavailable(e) from e
    except HTTPException:
        raise
    except Exception as e:  # pylint: disable=broad-except
        raise _vault_internal_error(e, "read the secret") from e


@router.get(
    "/secret/versions",
    response_model=VaultSecretVersionsResponse,
    summary="List versions of a secret",
)
def list_secret_versions(
    path: str = Query(..., description="Path to the secret"),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin", "maintainer")
    ),  # pylint: disable=unused-argument
):
    """
    List versions of a secret.
    """
    vault_service = VaultService(db)
    try:
        metadata = vault_service.read_secret_metadata(path)
        if metadata is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Secret not found at path: {path}",
            )

        versions = list(metadata.get("versions", {}).keys())
        versions = [int(v) for v in versions]
        current_version = metadata.get("current_version", 0)

        return {
            "versions": versions,
            "current_version": current_version,
            "path": path,
        }
    except VaultConnectionError as e:
        raise _vault_unavailable(e) from e
    except HTTPException:
        raise
    except Exception as e:  # pylint: disable=broad-except
        raise _vault_internal_error(e, "list secret versions") from e


@router.get(
    "/secret/version",
    response_model=VaultSecretVersionResponse,
    summary="Read a specific version of a secret",
)
def read_secret_version(
    request: Request,
    path: str = Query(..., description="Path to the secret"),
    version: int = Query(..., description="Version number"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "maintainer")),
):
    """
    Read a specific version of a secret.
    """
    vault_service = VaultService(db)
    try:
        data = vault_service.read_secret_version(path, version)
        if data is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Secret version {version} not found at path: {path}",
            )
        _emit_vault_secret_audit(
            db,
            request,
            current_user,
            "vault.secret.read",
            path,
            extra={"version": version},
        )

        # Get metadata to find creation time
        metadata = vault_service.read_secret_metadata(path)
        created_time = "unknown"
        if metadata and "versions" in metadata and str(version) in metadata["versions"]:
            created_time = metadata["versions"][str(version)].get(
                "created_time", "unknown"
            )

        return {
            "version": version,
            "created_time": created_time,
            "data": data,
        }
    except VaultConnectionError as e:
        raise _vault_unavailable(e) from e
    except HTTPException:
        raise
    except Exception as e:  # pylint: disable=broad-except
        raise _vault_internal_error(e, "read the secret version") from e


@router.post(
    "/secret",
    response_model=Dict[str, bool],
    status_code=status.HTTP_201_CREATED,
    summary="Create or update a secret",
)
def create_secret(
    secret: VaultSecretCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "maintainer")),
):
    """
    Create or update a secret in Vault.
    """
    vault_service = VaultService(db)
    try:
        success = vault_service.write_secret(secret.path, secret.data)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to write secret at path: {secret.path}",
            )
        _emit_vault_secret_audit(
            db, request, current_user, "vault.secret.write", secret.path
        )
        return {"success": True}
    except VaultConnectionError as e:
        raise _vault_unavailable(e) from e
    except HTTPException:
        raise
    except Exception as e:  # pylint: disable=broad-except
        raise _vault_internal_error(e, "write the secret") from e


@router.patch(
    "/secret/password",
    response_model=Dict[str, bool],
    summary="Update a password in a secret",
)
def update_secret_password(
    body: VaultSecretPasswordUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "maintainer")),
):
    """
    Update a password for a specific username in a secret.

    This endpoint allows updating just the password field while preserving other data in the secret.
    """
    vault_service = VaultService(db)
    try:
        success = vault_service.update_secret_password(
            body.path, body.username, body.new_password
        )
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to update password at path: {body.path}",
            )
        _emit_vault_secret_audit(
            db,
            request,
            current_user,
            "vault.secret.password_update",
            body.path,
            extra={"username": body.username},
        )
        return {"success": True}
    except VaultConnectionError as e:
        raise _vault_unavailable(e) from e
    except VaultSecretError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except HTTPException:
        raise
    except Exception as e:  # pylint: disable=broad-except
        raise _vault_internal_error(e, "update the password") from e


@router.delete(
    "/secret",
    response_model=Dict[str, bool],
    summary="Delete a secret",
)
def delete_secret(
    request: Request,
    path: str = Query(..., description="Path to the secret"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "maintainer")),
):
    """
    Delete a secret from Vault.
    """
    vault_service = VaultService(db)
    try:
        success = vault_service.delete_secret(path)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to delete secret at path: {path}",
            )
        _emit_vault_secret_audit(db, request, current_user, "vault.secret.delete", path)
        return {"success": True}
    except VaultConnectionError as e:
        raise _vault_unavailable(e) from e
    except HTTPException:
        raise
    except Exception as e:  # pylint: disable=broad-except
        raise _vault_internal_error(e, "delete the secret") from e
