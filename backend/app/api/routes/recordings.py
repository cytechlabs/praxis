"""Session recording REST endpoints (PRA-141)."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session as DbSession

from ...core.auth import get_current_user, require_role
from ...db.access_models import Recording
from ...db.access_models import Session as SessionRow
from ...db.models import User
from ...db.session import get_db
from ...services import recording_service
from ...services.access_authorization_service import scoped_system_ids

router = APIRouter(redirect_slashes=False)


def _enforce_recording_scope(rec: Recording, scope) -> None:
    """PRA-281: a scoped caller may only touch a recording whose ``system_id`` is
    in fleet scope. Out-of-scope (including the caller's OWN recording on a system
    now out of scope) is a non-disclosing 404 evaluated BEFORE ownership,
    metadata enrichment, cast streaming, or file deletion. Admin (scope ``None``)
    is unaffected."""
    if scope is not None and rec.system_id not in scope:
        raise HTTPException(status_code=404, detail="recording not found")


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


def _to_dict(r: Recording) -> Dict[str, Any]:
    return {
        "id": r.id,
        "session_id": r.session_id,
        "user_id": r.user_id,
        "system_id": r.system_id,
        "size_bytes": r.size_bytes,
        "frame_count": r.frame_count,
        "started_at": _iso(r.started_at),
        "ended_at": _iso(r.ended_at),
        "retention_expires_at": _iso(r.retention_expires_at),
        "status": r.status,
    }


def _assert_access(rec: Recording, current_user: User) -> None:
    if rec.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="not your recording")


@router.get("", response_model=Dict[str, Any])
async def list_recordings(
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
    mine_only: bool = Query(True),
    system_id: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
):
    q = db.query(Recording)
    if not (current_user.is_admin and not mine_only):
        q = q.filter(Recording.user_id == current_user.id)
    # PRA-281: an explicit out-of-scope system_id filter is a non-disclosing 404
    # before the query; otherwise fleet-scope the rows (empty scope → nothing).
    scope = scoped_system_ids(db, current_user)
    if system_id is not None:
        if scope is not None and system_id not in scope:
            raise HTTPException(status_code=404, detail=f"System {system_id} not found")
        q = q.filter(Recording.system_id == system_id)
    elif scope is not None:
        if not scope:
            from sqlalchemy import false

            q = q.filter(false())
        else:
            q = q.filter(Recording.system_id.in_(scope))
    if status is not None:
        q = q.filter(Recording.status == status)
    rows = q.order_by(Recording.id.desc()).limit(200).all()
    return {"status": "success", "recordings": [_to_dict(r) for r in rows]}


@router.get("/{recording_id}", response_model=Dict[str, Any])
async def get_recording(
    recording_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    rec = db.query(Recording).filter(Recording.id == recording_id).first()
    if rec is None:
        raise HTTPException(status_code=404, detail="recording not found")
    _enforce_recording_scope(rec, scoped_system_ids(db, current_user))
    _assert_access(rec, current_user)
    # enrich with session hostname for the UI
    session = db.query(SessionRow).filter(SessionRow.id == rec.session_id).first()
    hostname = None
    if session is not None and session.system is not None:
        hostname = session.system.hostname
    return {
        "status": "success",
        "recording": {
            **_to_dict(rec),
            "hostname": hostname,
            "login": session.login if session else None,
        },
    }


@router.get("/{recording_id}/cast")
async def stream_cast(
    recording_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    """Stream the raw asciinema v2 .cast file.

    Used by the replay UI and by operators downloading for offline review.
    """
    rec = db.query(Recording).filter(Recording.id == recording_id).first()
    if rec is None:
        raise HTTPException(status_code=404, detail="recording not found")
    # PRA-281: scope gate BEFORE ownership and BEFORE streaming any cast bytes.
    _enforce_recording_scope(rec, scoped_system_ids(db, current_user))
    _assert_access(rec, current_user)
    if rec.status == "pruned" or not rec.file_path or not os.path.exists(rec.file_path):
        raise HTTPException(status_code=410, detail="recording file unavailable")
    return StreamingResponse(
        recording_service.stream_cast(rec),
        media_type="application/x-asciicast",
        headers={
            "Content-Disposition": f'attachment; filename="session-{rec.session_id}.cast"',
            # Replay needs an actual-length hint when possible; the writer may
            # still be appending if the session is live, so prefer streaming.
            "X-Recording-Status": rec.status,
        },
    )


@router.delete("/{recording_id}", response_model=Dict[str, Any])
async def delete_recording(
    recording_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),
    db: DbSession = Depends(get_db),
):
    rec = db.query(Recording).filter(Recording.id == recording_id).first()
    if rec is None:
        raise HTTPException(status_code=404, detail="recording not found")
    # PRA-281: scope gate BEFORE file deletion / status mutation (admin-only route,
    # so a no-op for tenant-wide admins but future-proof and non-disclosing).
    _enforce_recording_scope(rec, scoped_system_ids(db, current_user))
    try:
        if rec.file_path and os.path.exists(rec.file_path):
            os.unlink(rec.file_path)
    except OSError:
        pass
    rec.status = "pruned"
    db.commit()
    return {"status": "success", "message": "recording pruned"}
