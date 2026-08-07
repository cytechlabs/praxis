"""
Command execution API routes.
Provides endpoints for secure command execution, validation, and monitoring.
"""

import logging
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...core.api_errors import internal_error
from ...core.auth import get_current_user, require_role, require_system_access
from ...core.rate_limit import limiter
from ...db.models import User
from ...db.session import get_db
from ...services.access_authorization_service import (
    scoped_system_ids,
    user_can_access_system,
)
from ...services.command_execution_service import (
    CommandExecutionError,
    CommandExecutionService,
)

logger = logging.getLogger(__name__)

router = APIRouter()


class CommandExecutionRequest(BaseModel):
    """Request model for command execution."""

    system_id: int = Field(..., description="ID of the target system")
    command: str = Field(..., description="Command to execute", min_length=1)
    timeout_seconds: Optional[int] = Field(
        None, description="Execution timeout in seconds"
    )
    session_id: Optional[str] = Field(None, description="Session identifier")
    bypass_validation: bool = Field(
        False, description="Whether to bypass command validation"
    )
    execution_context: Optional[Dict] = Field(
        None, description="Additional execution context"
    )


class CommandExecutionResponse(BaseModel):
    """Response model for command execution."""

    id: int
    system_id: int
    system_hostname: Optional[str] = None
    user_id: int
    username: Optional[str] = None
    session_id: Optional[str]
    command: str
    normalized_command: Optional[str] = None
    command_hash: str
    execution_status: str
    exit_code: Optional[int]
    stdout: Optional[str]
    stderr: Optional[str]
    started_at: Optional[str]
    completed_at: Optional[str]
    execution_time_ms: Optional[int]
    timeout_seconds: int
    max_memory_usage_bytes: Optional[int]
    cpu_time_ms: Optional[int]
    validation_status: str
    risk_level: str
    requires_sudo: bool
    actual_user: Optional[str]
    error_type: Optional[str]
    error_message: Optional[str]
    retry_count: int
    execution_context: Optional[Dict]


class ActiveExecutionResponse(BaseModel):
    """Response model for active executions."""

    execution_id: int
    system_id: int
    system_hostname: str
    command: str
    start_time: float
    timeout: int
    elapsed_time: float


class ExecutionTestResponse(BaseModel):
    """Response model for execution tests."""

    system_id: int
    test_status: str
    execution_time_ms: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    error_message: Optional[str] = None
    tested_at: str


@router.post("/execute", response_model=CommandExecutionResponse)
@limiter.limit("30/minute")
def execute_command(
    request: Request,
    body: CommandExecutionRequest,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Execute a command on a remote system.

    This endpoint provides secure command execution with comprehensive monitoring,
    validation, timeout management, and resource limits.

    PRA-305: the Starlette request parameter MUST be named ``request`` — SlowAPI's
    ``@limiter.limit`` resolves the rate-limit key by looking up a parameter named
    exactly ``request`` and raises before the body runs if it is missing/mistyped.
    The Pydantic command payload is therefore bound as ``body``.
    """
    try:
        # PRA-139: gate on fleet access authorization before invoking the
        # executor. Admins pass via the implicit grant the binding service
        # materialises for every system.
        from ...db.models import System as _System
        from ...services.access_authorization_service import (
            PermissionDenied,
            enforce_action,
        )

        target_system = db.query(_System).filter(_System.id == body.system_id).first()
        if target_system is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="System not found"
            )
        try:
            enforce_action(db, current_user, target_system, "command_exec")
        except PermissionDenied as pd:
            # PRA-143: log denial for SIEM correlation
            from ...services.audit_event_service import safe_emit

            safe_emit(
                db=db,
                action="command.exec",
                outcome="denied",
                actor_user_id=current_user.id,
                actor_username=current_user.username,
                actor_ip=request.client.host if request.client else None,
                target_system_id=target_system.id,
                target_kind="system",
                target_id=str(target_system.id),
                context={"reason_code": pd.code, "reason": pd.reason},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": pd.code, "reason": pd.reason},
            ) from pd

        service = CommandExecutionService(db)

        # Only admins can bypass command validation
        bypass = body.bypass_validation and current_user.is_admin

        result = service.execute_command(
            system_id=body.system_id,
            user_id=current_user.id,
            command=body.command,
            timeout_seconds=body.timeout_seconds,
            session_id=body.session_id,
            bypass_validation=bypass,
            execution_context=body.execution_context,
        )

        # PRA-143: emit the command exec event so SIEM + audit UI have a record
        try:
            from ...services.audit_event_service import safe_emit

            outcome = "success" if result.get("status") == "success" else "failure"
            safe_emit(
                db=db,
                action="command.exec",
                outcome=outcome,
                actor_user_id=current_user.id,
                actor_username=current_user.username,
                actor_ip=request.client.host if request.client else None,
                target_system_id=target_system.id,
                target_kind="system",
                target_id=str(target_system.id),
                context={
                    "command": body.command,
                    "exit_code": result.get("exit_code"),
                    "execution_time_ms": result.get("execution_time_ms"),
                    "bypass_validation": bypass,
                },
            )
        except Exception:  # pylint: disable=broad-except
            pass

        return CommandExecutionResponse(**result)

    except HTTPException:
        # PRA-132: let HTTPExceptions raised by the service (e.g. the 402
        # entitlement block on the paid approval workflow) propagate unchanged
        # instead of being reshaped into a 500 by the broad handler below.
        raise
    except CommandExecutionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
        ) from e
    except Exception as e:
        raise internal_error(
            e, context="Command execution failed", logger=logger
        ) from e


@router.get("/history", response_model=List[CommandExecutionResponse])
def get_execution_history(
    system_id: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get command execution history.

    Returns a list of previous command executions with optional filtering by system.
    """
    # PRA-281: a specific system_id must be in the caller's fleet scope; out of
    # scope (or nonexistent) returns a non-disclosing 404.
    if system_id is not None and not user_can_access_system(
        db, current_user, system_id
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="System not found"
        )
    try:
        service = CommandExecutionService(db)

        # Regular users can only see their own executions
        user_id = None if current_user.is_admin else current_user.id

        results = service.get_execution_history(
            system_id=system_id,
            user_id=user_id,
            limit=min(limit, 1000),  # Cap at 1000 results
            offset=offset,
            system_ids=scoped_system_ids(db, current_user),
        )

        return [CommandExecutionResponse(**result) for result in results]

    except Exception as e:
        raise internal_error(
            e, context="retrieve execution history", logger=logger
        ) from e


@router.get("/active", response_model=List[ActiveExecutionResponse])
def get_active_executions(
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Get currently active command executions.

    Returns a list of commands that are currently being executed.
    Requires admin or maintainer role.
    """
    try:
        service = CommandExecutionService(db)

        # PRA-281: only active executions on systems in the caller's fleet scope.
        active_executions = service.get_active_executions(
            system_ids=scoped_system_ids(db, current_user)
        )

        return [ActiveExecutionResponse(**execution) for execution in active_executions]

    except Exception as e:
        raise internal_error(
            e, context="retrieve active executions", logger=logger
        ) from e


@router.delete("/active/{execution_id}")
def kill_execution(
    execution_id: int,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """
    Kill an active command execution.

    Terminates a running command execution by its ID.
    Requires admin or maintainer role.
    """
    try:
        service = CommandExecutionService(db)

        # PRA-281: refuse to kill an execution on a system outside the caller's
        # fleet scope — kill_execution returns False, mapped to the same
        # non-disclosing 404 as a missing execution.
        success = service.kill_execution(
            execution_id, allowed_system_ids=scoped_system_ids(db, current_user)
        )

        if success:
            return {"message": f"Execution {execution_id} terminated successfully"}

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution {execution_id} not found or already completed",
        )

    except HTTPException:
        raise
    except Exception as e:
        raise internal_error(e, context="kill execution", logger=logger) from e


@router.post(
    "/test/{system_id}",
    response_model=ExecutionTestResponse,
    dependencies=[Depends(require_system_access("admin", "maintainer"))],
)
def test_command_execution(
    system_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Test command execution capability on a system.

    Runs a simple test command to verify that command execution is working
    properly on the specified system.
    Requires admin or maintainer role.
    """
    try:
        service = CommandExecutionService(db)

        result = service.test_command_execution(
            system_id=system_id,
            user_id=current_user.id,
        )

        return ExecutionTestResponse(**result)

    except Exception as e:
        raise internal_error(
            e, context="Command execution test failed", logger=logger
        ) from e


@router.get("/result/{execution_id}", response_model=CommandExecutionResponse)
def get_execution_result(
    execution_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get a specific command execution result by ID.

    Returns detailed information about a specific command execution.
    """
    try:
        service = CommandExecutionService(db)

        # PRA-281: a command result carries a system_id, so this is a
        # system-addressable read. Constrain the search to the caller's fleet
        # scope FIRST (admins -> None -> tenant-wide), so a result on a system
        # outside the caller's grants is invisible — including their own historical
        # result on a system that has since left their scope.
        results = service.get_execution_history(
            limit=1000, system_ids=scoped_system_ids(db, current_user)
        )

        # Find the specific execution within the in-scope results.
        execution_result = None
        for result in results:
            if result["id"] == execution_id:
                # Ownership is preserved WITHIN scope: a non-admin may still only
                # view their own results (product policy), even on a system they
                # can otherwise access.
                if not current_user.is_admin and result["user_id"] != current_user.id:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="You don't have permission to view this execution",
                    )
                execution_result = result
                break

        if not execution_result:
            # Missing OR out-of-scope -> the same non-disclosing 404, so an
            # out-of-scope execution id never reveals its existence.
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution {execution_id} not found",
            )

        return CommandExecutionResponse(**execution_result)

    except HTTPException:
        raise
    except Exception as e:
        raise internal_error(
            e, context="retrieve execution result", logger=logger
        ) from e
