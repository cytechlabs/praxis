"""
Vault API routes.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ....core.auth import require_role
from ....db.models import User
from ....db.session import get_db
from ....services.vault_service import VaultService
from ...schemas.vault.vault import (
    VaultConfigCreate,
    VaultConfigResponse,
    VaultConfigUpdate,
)

router = APIRouter()


@router.post(
    "",
    response_model=VaultConfigResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new Vault configuration",
)
def create_vault_config(
    config: VaultConfigCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "maintainer")),
):
    """
    Create a new Vault configuration.
    """
    vault_service = VaultService(db)
    try:
        new_config = vault_service.create_config(
            is_internal=config.is_internal,
            server_url=config.server_url,
            user_id=current_user.id,
        )
        return new_config
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create Vault configuration: {str(e)}",
        ) from e


@router.get(
    "",
    response_model=List[VaultConfigResponse],
    summary="List all Vault configurations",
)
def list_vault_configs(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin", "maintainer")
    ),  # pylint: disable=unused-argument
):
    """
    List all Vault configurations.
    """
    vault_service = VaultService(db)
    return vault_service.list_configs()


@router.get(
    "/active",
    response_model=VaultConfigResponse,
    summary="Get the active Vault configuration",
)
def get_active_vault_config(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin", "maintainer")
    ),  # pylint: disable=unused-argument
):
    """
    Get the active Vault configuration.
    """
    vault_service = VaultService(db)
    config = vault_service.get_active_config()
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active Vault configuration found",
        )
    return config


@router.get(
    "/{config_id}",
    response_model=VaultConfigResponse,
    summary="Get a specific Vault configuration",
)
def get_vault_config(
    config_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin", "maintainer")
    ),  # pylint: disable=unused-argument
):
    """
    Get a specific Vault configuration.
    """
    vault_service = VaultService(db)
    config = vault_service.get_config(config_id)
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault configuration with ID {config_id} not found",
        )
    return config


@router.put(
    "/{config_id}",
    response_model=VaultConfigResponse,
    summary="Update a Vault configuration",
)
def update_vault_config(
    config_id: int,
    config: VaultConfigUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "maintainer")),
):  # pylint: disable=unused-argument
    """
    Update a Vault configuration.
    """
    vault_service = VaultService(db)
    updated_config = vault_service.update_config(
        config_id=config_id,
        is_internal=config.is_internal,
        server_url=config.server_url,
    )
    if not updated_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault configuration with ID {config_id} not found",
        )
    return updated_config


@router.post(
    "/{config_id}/activate",
    response_model=VaultConfigResponse,
    summary="Activate a Vault configuration",
)
def activate_vault_config(
    config_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "maintainer")),
):  # pylint: disable=unused-argument
    """
    Activate a specific Vault configuration.
    """
    vault_service = VaultService(db)
    activated_config = vault_service.activate_config(config_id)
    if not activated_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault configuration with ID {config_id} not found",
        )
    return activated_config


@router.delete(
    "/{config_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a Vault configuration",
)
def delete_vault_config(
    config_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "maintainer")),
):  # pylint: disable=unused-argument
    """
    Delete a Vault configuration.
    """
    vault_service = VaultService(db)
    success = vault_service.delete_config(config_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault configuration with ID {config_id} not found",
        )
    # No return needed for status code 204


# Health endpoint moved to __init__.py
