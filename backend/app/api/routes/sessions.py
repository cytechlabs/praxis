"""REST + WebSocket endpoints for interactive sessions (PRA-140)."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import jwt
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from ...core.auth import ALGORITHM, SECRET_KEY, get_current_user
from ...db.access_models import FleetRole
from ...db.access_models import Session as SessionRow
from ...db.models import System, User
from ...db.session import SessionLocal, get_db
from ...services import session_runtime as rt_registry
from ...services import session_service
from ...services.access_authorization_service import (
    scope_query_by_system,
    user_can_access_system,
)
from ...services.audit_event_service import safe_emit

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)


# --------------------------------------------------------------- schemas


class OpenSessionBody(BaseModel):
    system_id: int
    login: Optional[str] = Field(None, max_length=100)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


def _is_admin_or_maintainer(user: User) -> bool:
    """PRA-145: ops visibility gate. Maintainers are the operator role for fleet
    hygiene. PRA-281 additionally constrains a maintainer's operator reach to
    their fleet scope (see ``_operator_can_access``); admins are tenant-wide."""
    if user.is_admin:
        return True
    return any(r.name == "maintainer" for r in (user.roles or []))


def _operator_can_access(db: DbSession, user: User, row: SessionRow) -> bool:
    """PRA-281: whether ``user`` may act on another user's session as an operator.

    Requires the operator role (admin/maintainer) AND fleet scope on the session's
    system. Admins pass via tenant-wide scope. Callers use this to return a
    NON-DISCLOSING 404 (rather than 403) when a maintainer targets a session on a
    system outside their grants, so cross-scope session existence never leaks.
    """
    return _is_admin_or_maintainer(user) and user_can_access_system(
        db, user, row.system_id
    )


def _enrich_with_runtime_activity(
    base: Dict[str, Any], row: SessionRow
) -> Dict[str, Any]:
    """Overlay live PTY activity timestamp from the in-process registry.

    The DB column updates only on commit; the runtime tracks each keystroke
    in monotonic time. Active Sessions UI polls every 5s and needs the live
    figure to render an honest 'last activity' for filtering stale shells.
    Also surfaces the PRA-148 attached-subscriber list so the owner banner
    and the operator can see who's joined.
    """
    rt = rt_registry.get(row.id)
    if rt is None or rt.closed.is_set():
        return base
    # Translate monotonic last_activity into wall-clock by anchoring to now.
    import time as _t

    delta_s = max(0.0, _t.monotonic() - rt.last_activity)
    base["last_activity_at"] = _iso(datetime.utcnow() - timedelta(seconds=delta_s))
    base["live"] = True
    base["attached"] = rt.list_subscribers()
    return base


def _row_to_dict(
    row: SessionRow,
    *,
    hostname: Optional[str] = None,
    fleet_role_name: Optional[str] = None,
    enrich_runtime: bool = False,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "id": row.id,
        "user_id": row.user_id,
        "system_id": row.system_id,
        "hostname": hostname,
        "fleet_role_id": row.fleet_role_id,
        "fleet_role_name": fleet_role_name,
        "login": row.login,
        "status": row.status,
        "close_reason": row.close_reason,
        "started_at": _iso(row.started_at),
        "last_activity_at": _iso(row.last_activity_at),
        "ended_at": _iso(row.ended_at),
        "max_expires_at": _iso(row.max_expires_at),
        "client_ip": row.client_ip,
    }
    if enrich_runtime:
        _enrich_with_runtime_activity(out, row)
    return out


# --------------------------------------------------------------- REST


@router.post("", response_model=Dict[str, Any])
async def open_session(
    payload: OpenSessionBody,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    try:
        row, _ = session_service.open_session(
            db,
            current_user,
            payload.system_id,
            login=payload.login,
            client_ip=(http_request.client.host if http_request.client else None),
        )
    except session_service.ApprovalRequired as e:
        # PRA-147: not an error — caller polls /session-approvals/{id}
        # and re-tries open once state flips to "granted".
        return {
            "status": "pending",
            "approval_id": e.approval_id,
            "detail": "Session requires operator approval — request submitted.",
        }
    except session_service.SessionError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"status": "success", "session": _row_to_dict(row)}


@router.get("", response_model=Dict[str, Any])
async def list_sessions(
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
    mine_only: bool = Query(True),
    active_only: bool = Query(False),
):
    can_see_all = _is_admin_or_maintainer(current_user)
    q = db.query(SessionRow)
    if mine_only or not can_see_all:
        q = q.filter(SessionRow.user_id == current_user.id)
    else:
        # PRA-281: the operator view is scoped to sessions on systems in the
        # caller's fleet scope (admins are tenant-wide, so unfiltered).
        q = scope_query_by_system(q, db, current_user, SessionRow.system_id)
    if active_only:
        q = q.filter(SessionRow.status.in_(("opening", "active")))
    rows = q.order_by(SessionRow.id.desc()).limit(200).all()

    if not rows:
        return {"status": "success", "sessions": []}

    # Single round-trip lookups for join columns the UI renders.
    sys_ids = {r.system_id for r in rows}
    role_ids = {r.fleet_role_id for r in rows if r.fleet_role_id is not None}
    sys_map = {
        s.id: s.hostname
        for s in db.query(System.id, System.hostname)
        .filter(System.id.in_(sys_ids))
        .all()
    }
    role_map = (
        {
            r.id: r.name
            for r in db.query(FleetRole.id, FleetRole.name)
            .filter(FleetRole.id.in_(role_ids))
            .all()
        }
        if role_ids
        else {}
    )

    return {
        "status": "success",
        "sessions": [
            _row_to_dict(
                r,
                hostname=sys_map.get(r.system_id),
                fleet_role_name=role_map.get(r.fleet_role_id),
                enrich_runtime=True,
            )
            for r in rows
        ],
    }


@router.get("/{session_id}", response_model=Dict[str, Any])
async def get_session(
    session_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    row = db.query(SessionRow).filter(SessionRow.id == session_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="session not found")
    if row.user_id != current_user.id:
        if not _is_admin_or_maintainer(current_user):
            raise HTTPException(status_code=403, detail="not your session")
        # PRA-281: an operator out of fleet scope sees the session as nonexistent.
        if not user_can_access_system(db, current_user, row.system_id):
            raise HTTPException(status_code=404, detail="session not found")
    return {"status": "success", "session": _row_to_dict(row, enrich_runtime=True)}


@router.post("/{session_id}/force-close", response_model=Dict[str, Any])
async def force_close_session(
    http_request: Request,
    session_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    """Operator cut-off (PRA-145). Closes the session regardless of owner.

    Distinct from ``/close`` so the audit log can split self-close from
    forced-close cleanly. The runtime callback would otherwise emit a
    plain ``session.close`` — we emit ``session.force_close`` here so
    SIEM rules see one event with the operator identity in ``actor``.
    """
    if not _is_admin_or_maintainer(current_user):
        raise HTTPException(status_code=403, detail="admin or maintainer required")
    row = db.query(SessionRow).filter(SessionRow.id == session_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="session not found")
    # PRA-281: an operator may only force-close sessions on systems in their scope.
    if not _operator_can_access(db, current_user, row):
        raise HTTPException(status_code=404, detail="session not found")
    if row.status not in ("opening", "active"):
        raise HTTPException(status_code=409, detail=f"session already {row.status}")
    updated = session_service.close_session(db, session_id, reason="admin_force")
    safe_emit(
        db=db,
        action="session.force_close",
        actor_user_id=current_user.id,
        actor_username=current_user.username,
        actor_ip=http_request.client.host if http_request.client else None,
        target_system_id=row.system_id,
        target_kind="session",
        target_id=str(row.id),
        context={
            "subject_user_id": row.user_id,
            "login": row.login,
            "reason": "admin_force",
        },
    )
    return {"status": "success", "session": _row_to_dict(updated or row)}


@router.post("/{session_id}/ws-ticket", response_model=Dict[str, Any])
async def ws_ticket(
    session_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    """Mint a short-lived WebSocket ticket for the session owner.

    Browsers can't attach Authorization to ws:// upgrades easily, and our
    access token lives in an httpOnly cookie. The UI calls this endpoint,
    receives a 30-second JWT bound to (session_id, user_id), then passes it
    as ``?token=`` on the WebSocket URL.
    """
    row = db.query(SessionRow).filter(SessionRow.id == session_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="session not found")
    if row.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="not your session")

    token = jwt.encode(
        {
            "sub": current_user.username,
            "session_id": session_id,
            "purpose": "ws-ticket",
            "exp": datetime.utcnow() + timedelta(seconds=30),
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )
    return {"status": "success", "token": token, "expires_in": 30}


@router.post("/{session_id}/join-ticket", response_model=Dict[str, Any])
async def join_ticket(
    session_id: int = Path(...),
    mode: str = Query("observe", pattern="^(observe|participate)$"),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    """Mint a short-lived ticket for an operator joining as moderator (PRA-148).

    Distinct ``purpose=ws-join-ticket`` so the WS handler can branch on
    join vs owner without conflating the access scope. Auth model for v1:
    admin and maintainer can join in either mode; everyone else 403.
    """
    if not _is_admin_or_maintainer(current_user):
        raise HTTPException(status_code=403, detail="admin or maintainer required")
    row = db.query(SessionRow).filter(SessionRow.id == session_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="session not found")
    # PRA-281: an operator may only join sessions on systems in their fleet scope.
    if not _operator_can_access(db, current_user, row):
        raise HTTPException(status_code=404, detail="session not found")
    if row.status not in ("opening", "active"):
        raise HTTPException(status_code=409, detail=f"session {row.status}")
    if rt_registry.get(session_id) is None:
        raise HTTPException(status_code=410, detail="runtime missing")

    token = jwt.encode(
        {
            "sub": current_user.username,
            "session_id": session_id,
            "purpose": "ws-join-ticket",
            "mode": mode,
            "exp": datetime.utcnow() + timedelta(seconds=30),
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )
    return {"status": "success", "token": token, "expires_in": 30, "mode": mode}


@router.post("/{session_id}/close", response_model=Dict[str, Any])
async def close_session(
    session_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    row = db.query(SessionRow).filter(SessionRow.id == session_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="session not found")
    if row.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="not your session")
    updated = session_service.close_session(db, session_id, reason="client_close")
    return {"status": "success", "session": _row_to_dict(updated or row)}


# ----------------------------------------------------------- WebSocket


def _parse_ws_ticket(token: str, session_id: int) -> Optional[str]:
    """Decode an owner ws-ticket and return the username claim, or None.

    Accepts ONLY tickets minted with ``purpose="ws-ticket"`` bound to the
    matching session_id. Regular access tokens are refused even if valid —
    WS upgrades should never reuse the broad-scoped access token.
    """
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None
    if payload.get("purpose") != "ws-ticket":
        return None
    if payload.get("session_id") != session_id:
        return None
    username = payload.get("sub")
    if not isinstance(username, str) or not username:
        return None
    return username


def _parse_ws_join_ticket(token: str, session_id: int) -> Optional[Dict[str, str]]:
    """Decode a join-ticket (PRA-148). Returns {username, mode} or None."""
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None
    if payload.get("purpose") != "ws-join-ticket":
        return None
    if payload.get("session_id") != session_id:
        return None
    username = payload.get("sub")
    mode = payload.get("mode")
    if not isinstance(username, str) or not username:
        return None
    if mode not in ("observe", "participate"):
        return None
    return {"username": username, "mode": mode}


def _ws_authenticate(token: str, session_id: int) -> Optional[User]:
    """Validate an owner ws-ticket and return the matching User."""
    username = _parse_ws_ticket(token, session_id)
    if username is None:
        return None
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if user is None or not user.is_active:
            return None
        return user
    finally:
        db.close()


def _ws_authenticate_join(token: str, session_id: int) -> Optional[tuple[User, str]]:
    """Validate a join ticket. Returns (User, mode) or None."""
    parsed = _parse_ws_join_ticket(token, session_id)
    if parsed is None:
        return None
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == parsed["username"]).first()
        if user is None or not user.is_active:
            return None
        if not _is_admin_or_maintainer(user):
            return None
        return user, parsed["mode"]
    finally:
        db.close()


MOD_WRITE_AUDIT_INTERVAL_S = 30  # PRA-148: rate-limit moderator_write events


@router.websocket("/{session_id}/ws")
async def session_ws(
    websocket: WebSocket,
    session_id: int,
    token: str = Query(...),
):
    """Owner / moderator WebSocket attach (PRA-140 + PRA-148).

    Accepts either an ``ws-ticket`` (owner; can read+write) or a
    ``ws-join-ticket`` (admin/maintainer; observe = read-only,
    participate = read+write). Mode controls input handling and
    emits the corresponding session.moderator_* audit events.
    """
    # First try owner-ticket. If that fails, fall back to join-ticket.
    user: Optional[User] = _ws_authenticate(token, session_id)
    mode: str = "owner"
    if user is None:
        joined = _ws_authenticate_join(token, session_id)
        if joined is None:
            await websocket.close(code=4401, reason="unauthorized")
            return
        user, mode = joined

    db = SessionLocal()
    try:
        row = db.query(SessionRow).filter(SessionRow.id == session_id).first()
    finally:
        db.close()
    if row is None:
        await websocket.close(code=4404, reason="session not found")
        return
    if mode == "owner" and row.user_id != user.id and not user.is_admin:
        await websocket.close(code=4403, reason="forbidden")
        return
    if row.status not in ("opening", "active"):
        await websocket.close(code=4410, reason=f"session {row.status}")
        return

    runtime = rt_registry.get(session_id)
    if runtime is None:
        await websocket.close(code=4410, reason="runtime missing")
        return

    await websocket.accept()
    loop = asyncio.get_running_loop()
    out_queue: "asyncio.Queue[Optional[bytes]]" = asyncio.Queue(maxsize=256)
    sid = runtime.attach(loop, out_queue, username=user.username, mode=mode)

    # PRA-148: marker frame in the recording + audit on join.
    if mode != "owner":
        try:
            from ...services.recording_service import add_marker

            add_marker(session_id, f"{user.username} joined as {mode}")
        except Exception:  # pylint: disable=broad-except
            pass
        safe_emit(
            db=None,
            action="session.moderator_join",
            actor_user_id=user.id,
            actor_username=user.username,
            target_system_id=row.system_id,
            target_kind="session",
            target_id=str(session_id),
            context={"mode": mode},
        )

    last_audit_emitted = 0.0

    async def pump_remote_to_browser():
        try:
            while True:
                data = await out_queue.get()
                if data is None:
                    break
                await websocket.send_bytes(data)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("session %d out-pump: %s", session_id, e)

    pumper = asyncio.create_task(pump_remote_to_browser())

    try:
        while True:
            msg = await websocket.receive()
            mtype = msg.get("type")
            if mtype == "websocket.disconnect":
                break
            # Observers must never write into the PTY — drop bytes/text input.
            if mode == "observe":
                continue
            if "bytes" in msg and msg["bytes"] is not None:
                runtime.write(msg["bytes"], sid=sid)
                if mode != "owner":
                    now = time.monotonic()
                    if now - last_audit_emitted > MOD_WRITE_AUDIT_INTERVAL_S:
                        last_audit_emitted = now
                        safe_emit(
                            db=None,
                            action="session.moderator_write",
                            actor_user_id=user.id,
                            actor_username=user.username,
                            target_system_id=row.system_id,
                            target_kind="session",
                            target_id=str(session_id),
                            context={"mode": mode},
                        )
                continue
            if "text" in msg and msg["text"] is not None:
                try:
                    ctrl = json.loads(msg["text"])
                except ValueError:
                    continue
                if ctrl.get("type") == "resize":
                    # Only the owner may resize — moderators piggyback the geometry.
                    if mode == "owner":
                        cols = int(ctrl.get("cols", 80))
                        rows = int(ctrl.get("rows", 24))
                        runtime.resize(cols, rows)
                elif ctrl.get("type") == "input":
                    payload = ctrl.get("data", "")
                    if isinstance(payload, str):
                        runtime.write(payload.encode("utf-8"), sid=sid)
    except WebSocketDisconnect:
        pass
    except Exception as e:  # pylint: disable=broad-except
        logger.warning("session %d ws loop: %s", session_id, e)
    finally:
        pumper.cancel()
        runtime.detach(sid)
        if mode != "owner":
            try:
                from ...services.recording_service import add_marker

                add_marker(session_id, f"{user.username} left ({mode})")
            except Exception:  # pylint: disable=broad-except
                pass
            safe_emit(
                db=None,
                action="session.moderator_leave",
                actor_user_id=user.id,
                actor_username=user.username,
                target_system_id=row.system_id,
                target_kind="session",
                target_id=str(session_id),
                context={"mode": mode},
            )
        try:
            await websocket.close()
        except Exception:  # pylint: disable=broad-except
            pass
