"""
Vault API routes.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ....core.auth import get_current_user
from ....db.models import User
from ....db.session import get_db
from ....services.vault_service import VaultConnectionError, VaultService
from ...schemas.vault.vault import VaultHealthResponse
from .secrets import router as vault_secrets_router
from .vault import router as vault_config_router

router = APIRouter()

# Include the vault configuration routes
router.include_router(vault_config_router, prefix="/config", tags=["vault-config"])

# Include the vault secrets management routes
router.include_router(vault_secrets_router, prefix="/secrets", tags=["vault-secrets"])


@router.get(
    "/health",
    response_model=VaultHealthResponse,
    summary="Check the health of the Vault connection",
)
def check_vault_health(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):  # pylint: disable=unused-argument
    """
    Check the health of the Vault connection.
    """
    vault_service = VaultService(db)
    try:
        health = vault_service.check_health()
        return health
    except VaultConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Vault connection error: {str(e)}",
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error checking Vault health: {str(e)}",
        ) from e
