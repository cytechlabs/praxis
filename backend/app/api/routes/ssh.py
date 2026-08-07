"""
API routes for SSH connection management.

Connection lifecycle only: test, close, and their fleet-wide sweeps. Running a
command on a host is not exposed here. That contract belongs to
``/command-execution/execute``, which applies validation, risk classification and
approvals before any transport runs; a second HTTP entry point into
``SSHService.execute_command`` would bypass all of it. ``SSHService``'s execute
methods remain internal transport primitives for package, facts, drift and
repository work.
"""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.orm import Session

from ...core.auth import require_role, require_system_access
from ...db.models import User
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
