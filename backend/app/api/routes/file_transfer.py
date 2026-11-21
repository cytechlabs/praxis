"""File transfer REST endpoints (PRA-142)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional
from urllib.parse import quote

import anyio
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from ...core.auth import get_current_user
from ...core.redaction import redact_text
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
    if msg.startswith(("forbidden:", "action_not_allowed:")):
        code = 403
    elif "not found" in msg:
        code = 404
    elif msg.startswith(("ssh_auth_failed", "ssh_connect_failed")):
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


_DOWNLOAD_BAD_GATEWAY = (
    "ssh_host_key_error",
    "sftp_open_failed",
    "download failed",
    "transfer incomplete",
)


def _download_status(msg: str) -> int:
    """Status for a download failure. Extends the shared mapping with the
    outcomes a download can report before its first byte; other operations keep
    the shared mapping unchanged."""
    if msg.startswith(("file too large", "transfer exceeded")):
        return 413
    if msg.startswith("host_cooling_down"):
        return 503
    if msg.startswith(_DOWNLOAD_BAD_GATEWAY):
        return 502
    try:
        _raise_http(fts.FileTransferError(msg))
    except HTTPException as e:
        return e.status_code
    return 400


def _handle_download_call(fn, *args, **kwargs):
    """Like ``_handle_service_call`` for downloads: statuses are extended and
    every detail is redacted, because a download is the one operation whose
    failures are reported before any body is sent."""
    from app.services.transport import TransportUnavailable, TransportUnsupported

    try:
        return fn(*args, **kwargs)
    except TransportUnavailable as e:
        raise HTTPException(status_code=503, detail=redact_text(str(e))) from e
    except TransportUnsupported as e:
        raise HTTPException(status_code=501, detail=redact_text(str(e))) from e
    except fts.FileTransferError as e:
        msg = redact_text(str(e))
        raise HTTPException(status_code=_download_status(msg), detail=msg) from e


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


class _DownloadResponse(StreamingResponse):
    """Streams a prepared download and always releases it.

    Starlette does not close a synchronous body iterator when the client goes
    away, so the stream is closed here on every exit path. That ends the host
    transfer, removes any spool file, and records an abandoned transfer as a
    failure instead of leaving it open or finishing it as a success.
    """

    def __init__(self, stream: Any, **kwargs: Any) -> None:
        super().__init__(stream, **kwargs)
        self._stream = stream

    async def __call__(self, scope, receive, send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            close = getattr(self._stream, "close", None)
            if close is not None:
                with anyio.CancelScope(shield=True):
                    await anyio.to_thread.run_sync(close)


def _content_disposition(path: str) -> str:
    """Attachment header that is always a valid latin-1 header value."""
    name = path.rsplit("/", 1)[-1] or "file"
    fallback = "".join(c if " " <= c <= "~" and c not in '"\\;' else "_" for c in name)
    header = f'attachment; filename="{fallback}"'
    if fallback != name:
        header += f"; filename*=UTF-8''{quote(name, safe='', errors='replace')}"
    return header


@router.get("/{system_id}/download")
def download(
    request: Request,
    system_id: int = Path(...),
    path: str = Query(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    """Download a remote file.

    Client contract: authorization, file, connection and size-cap problems
    are ordinary error responses (403, 404, 400, 413, 502, 503) with a JSON
    ``detail``. A 200 is a complete file only if the body matches the
    ``Content-Length`` header; a transfer that fails after the 200 has been
    sent cannot change its status, so the connection is aborted and the body
    ends short of the declared length (a transport-level error to HTTP
    clients and a failed download in browsers). A zero-byte file is a 200 with
    ``Content-Length: 0``. Hosts that cannot report a size are streamed
    chunked, and an abort there appears as an unterminated chunked body. The
    agent transport receives the whole file before sending any header, so it
    never fails after the 200.
    """
    stream = _handle_download_call(
        fts.download_stream,
        db,
        current_user,
        system_id,
        path,
        client_ip=_client_ip(request),
    )
    try:
        headers = {"Content-Disposition": _content_disposition(path)}
        size = getattr(stream, "size", None)
        if size is not None:
            headers["Content-Length"] = str(size)
        return _DownloadResponse(
            stream, media_type="application/octet-stream", headers=headers
        )
    except Exception:
        close = getattr(stream, "close", None)
        if close is not None:
            close()
        raise


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
