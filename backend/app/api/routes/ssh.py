"""
API routes for SSH connection management.
"""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from sqlalchemy.orm import Session

from ...core.auth import require_role, require_system_access
from ...core.rate_limit import limiter
from ...db.models import System, User
from ...db.session import get_db
from ...services.access_authorization_service import scoped_system_ids
from ...services.ssh_service import SSHConnectionError, SSHService

router = APIRouter()


@router.get(
    "/test/{system_id}",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access("admin", "maintainer"))],
)
def test_connection(
    system_id: int = Path(..., description="The ID of the system to test"),
    current_user: User = Depends(
        require_role("admin", "maintainer")
    ),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    """
    Test SSH connection to a specific system.
    """
    try:
        ssh_service = SSHService(db)
        result = ssh_service.test_connection(system_id)
        return result
    except SSHConnectionError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error testing connection: {str(e)}"
        ) from e


@router.get("/test-all", response_model=List[Dict[str, Any]])
def test_all_connections(
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Test SSH connections to all active systems.
    """
    try:
        ssh_service = SSHService(db)
        # PRA-281: scoped callers sweep only their in-scope systems, never fleet.
        results = ssh_service.test_all_connections(
            scope_system_ids=scoped_system_ids(db, current_user)
        )
        return results
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error testing connections: {str(e)}"
        ) from e


@router.post(
    "/execute/{system_id}",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access("admin", "maintainer"))],
)
@limiter.limit("30/minute")
def execute_command(
    request: Request,
    command: str,
    system_id: int = Path(
        ..., description="The ID of the system to execute the command on"
    ),
    timeout: int = Query(None, description="Command execution timeout in seconds"),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Execute a command on a specific system.
    """
    try:
        # Check if the system exists
        system = db.query(System).filter(System.id == system_id).first()
        if not system:
            raise HTTPException(
                status_code=404, detail=f"System with ID {system_id} not found"
            )

        ssh_service = SSHService(db)
        result = ssh_service.execute_command(
            system_id, command, timeout, user_id=current_user.id
        )
        return result
    except SSHConnectionError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error executing command: {str(e)}"
        ) from e


@router.delete(
    "/close/{system_id}",
    response_model=Dict[str, bool],
    dependencies=[Depends(require_system_access("admin", "maintainer"))],
)
def close_connection(
    system_id: int = Path(
        ..., description="The ID of the system to close the connection for"
    ),
    current_user: User = Depends(
        require_role("admin", "maintainer")
    ),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    """
    Close SSH connection to a specific system.
    """
    try:
        ssh_service = SSHService(db)
        result = ssh_service.close_connection(system_id)
        return {"success": result}
    except SSHConnectionError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error closing connection: {str(e)}"
        ) from e


@router.delete("/close-all", response_model=Dict[str, int])
def close_all_connections(
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Close all SSH connections.
    """
    try:
        ssh_service = SSHService(db)
        # PRA-281: scoped callers close only their in-scope connections.
        closed_count = ssh_service.close_all_connections(
            scope_system_ids=scoped_system_ids(db, current_user)
        )
        return {"closed_count": closed_count}
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error closing connections: {str(e)}"
        ) from e
