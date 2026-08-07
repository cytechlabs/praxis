"""File transfer REST endpoints (PRA-142)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from ...core.auth import get_current_user
from ...db.access_models import FileTransferAudit
from ...db.models import User
from ...db.session import get_db
from ...services import file_transfer_service as fts
from ...services.access_authorization_service import (
    scoped_system_ids,
    user_can_access_system,
)

router = APIRouter(redirect_slashes=False)


class PathBody(BaseModel):
    path: str = Field(..., min_length=1, max_length=4096)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


def _audit_to_dict(row: FileTransferAudit) -> Dict[str, Any]:
    return {
        "id": row.id,
        "user_id": row.user_id,
        "system_id": row.system_id,
        "login": row.login,
        "direction": row.direction,
        "remote_path": row.remote_path,
        "local_filename": row.local_filename,
        "size_bytes": row.size_bytes,
        "sha256": row.sha256,
        "status": row.status,
        "error_message": row.error_message,
        "client_ip": row.client_ip,
        "started_at": _iso(row.started_at),
        "ended_at": _iso(row.ended_at),
        # PRA-153 #3e: surface the transport attribution the service
        # writes so UI/dashboards can display + filter without a
        # separate model query.
        "transport": row.transport,
    }


def _client_ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _raise_http(exc: fts.FileTransferError) -> None:
    msg = str(exc)
    code = 400
    if msg.startswith("forbidden:") or msg.startswith("action_not_allowed:"):
        code = 403
    elif "not found" in msg:
        code = 404
    elif msg.startswith("ssh_auth_failed") or msg.startswith("ssh_connect_failed"):
        # Host-side misconfiguration — fail fast with a clear 502.
        code = 502
    raise HTTPException(status_code=code, detail=msg)


def _handle_service_call(fn, *args, **kwargs):
    """Run a file_transfer_service call and translate every transport
    exception to the right HTTP status. Without this, force-agent
    list/stat/mkdir/unlink and tunnel-down upload/download would
    bypass the FileTransferError handler and surface as 500s, even
    though the service already wrote the audit row.
    """
    from app.services.transport import TransportUnavailable, TransportUnsupported

    try:
        return fn(*args, **kwargs)
    except TransportUnavailable as e:
        # Operator forced agent but tunnel is down — 503 reads as
        # "the system is up but this transport isn't available."
        raise HTTPException(status_code=503, detail=str(e))
    except TransportUnsupported as e:
        # Op cannot be served by the chosen transport (force-agent
        # asking for a directory op). 501 = Not Implemented for this
        # transport choice, audit-friendly + UI-displayable.
        raise HTTPException(status_code=501, detail=str(e))
    except fts.FileTransferError as e:
        _raise_http(e)


# --------------------------------------------------------------- endpoints


@router.get("/{system_id}/listdir", response_model=Dict[str, Any])
def listdir(
    system_id: int = Path(...),
    path: str = Query("/"),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    entries = _handle_service_call(fts.listdir, db, current_user, system_id, path)
    return {"status": "success", "path": path, "entries": entries}


@router.get("/{system_id}/stat", response_model=Dict[str, Any])
def stat(
    system_id: int = Path(...),
    path: str = Query(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    info = _handle_service_call(fts.stat, db, current_user, system_id, path)
    return {"status": "success", **info}


@router.get("/{system_id}/download")
def download(
    request: Request,
    system_id: int = Path(...),
    path: str = Query(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    stream = _handle_service_call(
        fts.download_stream,
        db,
        current_user,
        system_id,
        path,
        client_ip=_client_ip(request),
    )
    filename = (path.rsplit("/", 1)[-1] or "file").replace('"', "_")
    return StreamingResponse(
        stream,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.post("/{system_id}/upload", response_model=Dict[str, Any])
def upload(
    request: Request,
    system_id: int = Path(...),
    path: str = Query(..., description="absolute destination path on host"),
    file: UploadFile = None,
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    if file is None:
        raise HTTPException(status_code=400, detail="file part required")

    def _iter():
        while True:
            chunk = file.file.read(64 * 1024)
            if not chunk:
                break
            yield chunk

    result = _handle_service_call(
        fts.upload_stream,
        db,
        current_user,
        system_id,
        path,
        _iter(),
        local_filename=file.filename,
        client_ip=_client_ip(request),
    )
    return {"status": "success", **result}


@router.post("/{system_id}/mkdir", response_model=Dict[str, Any])
def mkdir(
    request: Request,
    body: PathBody,
    system_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    _handle_service_call(
        fts.mkdir,
        db,
        current_user,
        system_id,
        body.path,
        client_ip=_client_ip(request),
    )
    return {"status": "success"}


@router.delete("/{system_id}/unlink", response_model=Dict[str, Any])
def unlink(
    request: Request,
    system_id: int = Path(...),
    path: str = Query(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    _handle_service_call(
        fts.unlink,
        db,
        current_user,
        system_id,
        path,
        client_ip=_client_ip(request),
    )
    return {"status": "success"}


@router.get("/audits", response_model=Dict[str, Any])
def list_audit_log(
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
    system_id: Optional[int] = Query(None),
    mine_only: bool = Query(True),
):
    # PRA-281: FileTransferAudit.system_id is host-derived. An explicit
    # out-of-scope system_id filter is a non-disclosing 404, before any query.
    scope = scoped_system_ids(db, current_user)
    if (
        system_id is not None
        and scope is not None
        and not user_can_access_system(db, current_user, system_id)
    ):
        raise HTTPException(status_code=404, detail="System not found")

    uid = None if (current_user.is_admin and not mine_only) else current_user.id
    # Rows are additionally restricted to the caller's fleet scope so hidden
    # paths/filenames/errors/byte-counts/usernames never leak (admin scope=None
    # is unchanged; empty scope → no rows).
    rows = fts.list_audits(db, user_id=uid, system_id=system_id, system_ids=scope)
    return {"status": "success", "audits": [_audit_to_dict(r) for r in rows]}
