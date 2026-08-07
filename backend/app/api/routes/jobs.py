"""
API routes for job scheduling (PRA-75, PRA-8).
"""

import threading
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role
from ...db.models import User
from ...db.session import SessionLocal, get_db
from ...services.access_authorization_service import scoped_system_ids
from ...services.job_service import JobNotFound, JobService

router = APIRouter(redirect_slashes=False)


class JobCreate(BaseModel):
    """Request body for creating a job."""

    name: str
    description: Optional[str] = None
    job_type: str
    schedule: Optional[str] = None
    is_recurring: bool = False
    target_type: str
    target_ids: Optional[List[int]] = None
    package_filter: Optional[Dict[str, Any]] = None
    tag_match_logic: Optional[str] = "or"
    max_parallel: Optional[int] = 1
    depends_on_job_id: Optional[int] = None
    chain_condition: Optional[str] = "on_success"


class JobUpdate(BaseModel):
    """Request body for updating a job."""

    name: Optional[str] = None
    description: Optional[str] = None
    job_type: Optional[str] = None
    schedule: Optional[str] = None
    is_recurring: Optional[bool] = None
    status: Optional[str] = None
    target_type: Optional[str] = None
    target_ids: Optional[List[int]] = None
    package_filter: Optional[Dict[str, Any]] = None
    tag_match_logic: Optional[str] = None
    max_parallel: Optional[int] = None
    depends_on_job_id: Optional[int] = None
    chain_condition: Optional[str] = None


@router.get("", response_model=Dict[str, Any])
async def list_jobs(
    status: Optional[str] = Query(None, description="Filter by job status"),
    job_type: Optional[str] = Query(None, description="Filter by job type"),
    limit: int = Query(50, ge=1, le=200, description="Results per page"),
    offset: int = Query(0, ge=0, description="Results offset"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all jobs with optional filtering."""
    try:
        service = JobService(db, scope=scoped_system_ids(db, current_user))
        return service.list_jobs(
            status=status, job_type=job_type, limit=limit, offset=offset
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error listing jobs: {str(e)}"
        ) from e


@router.post("", response_model=Dict[str, Any])
async def create_job(
    body: JobCreate,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Create a new job."""
    try:
        service = JobService(db, scope=scoped_system_ids(db, current_user))
        return service.create_job(body.model_dump(), current_user.id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error creating job: {str(e)}"
        ) from e


@router.get("/chains", response_model=List[Dict[str, Any]])
async def get_job_chains(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """PRA-81: Get all job chains (jobs with dependencies)."""
    try:
        service = JobService(db, scope=scoped_system_ids(db, current_user))
        return service.get_job_chains()
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error getting job chains: {str(e)}"
        ) from e


@router.get("/active", response_model=List[Dict[str, Any]])
async def list_active_jobs(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all currently running jobs."""
    try:
        service = JobService(db, scope=scoped_system_ids(db, current_user))
        return service.get_active_jobs()
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error listing active jobs: {str(e)}"
        ) from e


@router.get("/failed", response_model=Dict[str, Any])
async def list_failed_jobs(
    limit: int = Query(50, ge=1, le=200, description="Results per page"),
    offset: int = Query(0, ge=0, description="Results offset"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List failed job runs."""
    try:
        service = JobService(db, scope=scoped_system_ids(db, current_user))
        return service.get_failed_jobs(limit=limit, offset=offset)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error listing failed jobs: {str(e)}",
        ) from e


@router.get("/history", response_model=Dict[str, Any])
async def list_all_history(
    limit: int = Query(50, ge=1, le=200, description="Results per page"),
    offset: int = Query(0, ge=0, description="Results offset"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all job execution history."""
    try:
        service = JobService(db, scope=scoped_system_ids(db, current_user))
        return service.get_all_history(limit=limit, offset=offset)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error listing job history: {str(e)}",
        ) from e


@router.get("/{job_id}", response_model=Dict[str, Any])
async def get_job(
    job_id: int = Path(..., description="The ID of the job"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get job details."""
    try:
        service = JobService(db, scope=scoped_system_ids(db, current_user))
        return service.get_job(job_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error getting job: {str(e)}"
        ) from e


@router.put("/{job_id}", response_model=Dict[str, Any])
async def update_job(
    body: JobUpdate,
    job_id: int = Path(..., description="The ID of the job"),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Update a job."""
    try:
        service = JobService(db, scope=scoped_system_ids(db, current_user))
        data = body.model_dump(exclude_unset=True)
        return service.update_job(job_id, data, current_user.id)
    except JobNotFound as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error updating job: {str(e)}"
        ) from e


@router.delete("/{job_id}", response_model=Dict[str, Any])
async def delete_job(
    job_id: int = Path(..., description="The ID of the job"),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Delete a job."""
    try:
        service = JobService(db, scope=scoped_system_ids(db, current_user))
        return service.delete_job(job_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error deleting job: {str(e)}"
        ) from e


def _run_job_background(
    job_id: int, user_id: int, ignore_maintenance_window: bool = False
):
    """Execute a job in a background thread with its own DB session."""
    db = SessionLocal()
    try:
        # PRA-281: scope was already enforced at the request boundary
        # (``start_job`` via the scoped service). This is post-authorization
        # execution, so it runs unscoped like the scheduler.
        service = JobService(db)
        service.run_job(
            job_id, user_id, ignore_maintenance_window=ignore_maintenance_window
        )
    except Exception as e:  # pylint: disable=broad-except
        import logging

        logging.getLogger(__name__).error(
            "Background job %d failed: %s", job_id, str(e)
        )
    finally:
        db.close()


@router.post("/{job_id}/run", response_model=Dict[str, Any])
async def run_job(
    job_id: int = Path(..., description="The ID of the job to run"),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Trigger immediate execution of a job."""
    try:
        service = JobService(db, scope=scoped_system_ids(db, current_user))
        history_id = service.start_job(job_id)
        thread = threading.Thread(
            target=_run_job_background,
            args=(job_id, current_user.id, True),
            daemon=True,
        )
        thread.start()
        return {
            "status": "success",
            "message": "Job started",
            "job_id": job_id,
            "history_id": history_id,
        }
    except JobNotFound as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error running job: {str(e)}"
        ) from e


@router.post("/{job_id}/dry-run", response_model=Dict[str, Any])
async def dry_run_job(
    job_id: int = Path(..., description="The ID of the job"),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """PRA-82: Preview what a job would do without executing it."""
    try:
        service = JobService(db, scope=scoped_system_ids(db, current_user))
        return service.dry_run_job(job_id)
    except JobNotFound as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error running dry-run: {str(e)}"
        ) from e


@router.post("/history/{history_id}/rollback", response_model=Dict[str, Any])
async def rollback_job_history(
    history_id: int = Path(..., description="The ID of the job history to rollback"),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """PRA-83: Rollback packages updated by a job execution."""
    try:
        service = JobService(db, scope=scoped_system_ids(db, current_user))
        return service.rollback_job_history(history_id, current_user.id)
    except JobNotFound as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error rolling back job: {str(e)}"
        ) from e


@router.post("/{job_id}/cancel", response_model=Dict[str, Any])
async def cancel_job_run(
    job_id: int = Path(..., description="The ID of the job to cancel"),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Cancel a running job."""
    try:
        service = JobService(db, scope=scoped_system_ids(db, current_user))
        return service.cancel_job_run(job_id)
    except JobNotFound as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error cancelling job: {str(e)}"
        ) from e


@router.get("/{job_id}/history", response_model=Dict[str, Any])
async def get_job_history(
    job_id: int = Path(..., description="The ID of the job"),
    limit: int = Query(50, ge=1, le=200, description="Results per page"),
    offset: int = Query(0, ge=0, description="Results offset"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get execution history for a specific job."""
    try:
        service = JobService(db, scope=scoped_system_ids(db, current_user))
        return service.get_job_history(job_id, limit=limit, offset=offset)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error getting job history: {str(e)}",
        ) from e
