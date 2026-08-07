"""Audit event + sink REST endpoints (PRA-143)."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from ...core.auth import get_current_user, require_role
from ...db.access_models import AuditEvent, AuditSink, AuditSinkDelivery
from ...db.models import User
from ...db.session import get_db
from ...services import audit_event_service as aes
from ...services import outbound_http_guard

router = APIRouter(redirect_slashes=False)


# ------------------------------------------------------------------ schemas


class AuditSinkCreate(BaseModel):
    name: str = Field(..., max_length=100)
    kind: str = Field(..., pattern="^(syslog|http|file)$")
    target: str = Field(..., max_length=1024)
    hmac_secret: Optional[str] = Field(None, max_length=256)
    config: Optional[Dict[str, Any]] = None
    enabled: bool = True


class AuditSinkUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    target: Optional[str] = Field(None, max_length=1024)
    hmac_secret: Optional[str] = Field(None, max_length=256)
    config: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


# ------------------------------------------------------------- helpers


# SSRF guardrail for operator-configured HTTP audit sinks. Sinks are admin-only,
# but the delivery worker POSTs to the target from inside the trust boundary, so
# the target is resolved and validated — loopback/link-local/private/metadata
# addresses are rejected and non-local targets must use TLS. Delivery revalidates
# and pins the connection independently. Set AUDIT_SINK_ALLOW_PRIVATE_TARGETS=1 to
# allow an internal on-network collector.
def _validate_http_sink_target(target: str) -> None:
    """Validate an ``http`` audit-sink target URL; raise ``HTTPException(400)`` on
    a disallowed target. Only applies to ``http`` sinks — syslog/file targets are
    not URLs and are left untouched. Delegates to the shared SSRF guard, which
    resolves DNS and fails closed on any disallowed resolved address."""
    try:
        outbound_http_guard.validate_target(
            target,
            allow_private=outbound_http_guard.allow_private_targets(),
            require_https=True,
        )
    except outbound_http_guard.SsrfBlocked as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _sink_to_dict(s: AuditSink, *, reveal_secret: bool = False) -> Dict[str, Any]:
    try:
        config = json.loads(s.config_json or "{}")
    except ValueError:
        config = {}
    return {
        "id": s.id,
        "name": s.name,
        "kind": s.kind,
        "target": s.target,
        # Never echo the secret by default; reveal only on explicit admin action.
        "hmac_secret_set": bool(s.hmac_secret),
        "hmac_secret": s.hmac_secret if reveal_secret else None,
        "config": config,
        "enabled": s.enabled,
        "created_at": s.created_at.isoformat() + "Z" if s.created_at else None,
    }


# ---------------------------------------------------------------- events


@router.get("/events", response_model=Dict[str, Any])
async def list_events(
    current_user: User = Depends(require_role("admin", "auditor")),
    db: DbSession = Depends(get_db),
    action: Optional[str] = Query(None),
    actor_user_id: Optional[int] = Query(None),
    system_id: Optional[int] = Query(None),
    outcome: Optional[str] = Query(None),
    since: Optional[datetime] = Query(None),
    until: Optional[datetime] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    q = db.query(AuditEvent)
    if action is not None:
        q = q.filter(AuditEvent.action == action)
    if actor_user_id is not None:
        q = q.filter(AuditEvent.actor_user_id == actor_user_id)
    if system_id is not None:
        q = q.filter(AuditEvent.target_system_id == system_id)
    if outcome is not None:
        q = q.filter(AuditEvent.outcome == outcome)
    if since is not None:
        q = q.filter(AuditEvent.timestamp >= since)
    if until is not None:
        q = q.filter(AuditEvent.timestamp <= until)
    total = q.count()
    rows = q.order_by(AuditEvent.id.desc()).offset(offset).limit(limit).all()
    return {
        "status": "success",
        "total": total,
        "events": [aes.event_to_dict(r) for r in rows],
    }


@router.get("/events/{event_id}", response_model=Dict[str, Any])
async def get_event(
    event_id: int = Path(...),
    current_user: User = Depends(require_role("admin", "auditor")),
    db: DbSession = Depends(get_db),
):
    row = db.query(AuditEvent).filter(AuditEvent.id == event_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="event not found")
    return {"status": "success", "event": aes.event_to_dict(row)}


@router.get("/schema", response_model=Dict[str, Any])
async def schema(
    current_user: User = Depends(get_current_user),
):
    """Machine-readable doc of the event shape + supported actions."""
    return {
        "status": "success",
        "schema_version": aes.SCHEMA_VERSION,
        "actions": sorted(
            [
                "session.open",
                "session.close",
                "session.idle_kill",
                "session.max_duration",
                "command.exec",
                "file.upload",
                "file.download",
                "file.mkdir",
                "file.unlink",
                "binding.create",
                "binding.delete",
                "access_request.create",
                "access_request.approve",
                "access_request.reject",
                "access_request.revoke",
                "totp.step_up",
            ]
        ),
        "wire_format": {
            "schema_version": "int",
            "event_uuid": "string",
            "timestamp": "ISO8601 UTC",
            "action": "dotted string",
            "outcome": "success | failure | denied",
            "actor": {"user_id": "int?", "username": "string?", "ip": "string?"},
            "target": {
                "kind": "string?",
                "system_id": "int?",
                "id": "string?",
            },
            "context": "object (per-action)",
        },
    }


# ------------------------------------------------------------------ sinks


@router.get("/sinks", response_model=Dict[str, Any])
async def list_sinks(
    current_user: User = Depends(require_role("admin")),
    db: DbSession = Depends(get_db),
):
    rows = db.query(AuditSink).order_by(AuditSink.id.asc()).all()
    return {"status": "success", "sinks": [_sink_to_dict(s) for s in rows]}


@router.post("/sinks", response_model=Dict[str, Any])
async def create_sink(
    payload: AuditSinkCreate,
    current_user: User = Depends(require_role("admin")),
    db: DbSession = Depends(get_db),
):
    if db.query(AuditSink).filter(AuditSink.name == payload.name).first():
        raise HTTPException(status_code=400, detail="sink name already in use")
    if payload.kind == "http":
        _validate_http_sink_target(payload.target)
    sink = AuditSink(
        name=payload.name,
        kind=payload.kind,
        target=payload.target,
        hmac_secret=payload.hmac_secret,
        config_json=json.dumps(payload.config or {}),
        enabled=payload.enabled,
    )
    db.add(sink)
    db.commit()
    db.refresh(sink)
    return {"status": "success", "sink": _sink_to_dict(sink)}


@router.patch("/sinks/{sink_id}", response_model=Dict[str, Any])
async def update_sink(
    sink_id: int = Path(...),
    payload: AuditSinkUpdate = None,
    current_user: User = Depends(require_role("admin")),
    db: DbSession = Depends(get_db),
):
    sink = db.query(AuditSink).filter(AuditSink.id == sink_id).first()
    if sink is None:
        raise HTTPException(status_code=404, detail="sink not found")
    if payload.name is not None:
        sink.name = payload.name
    if payload.target is not None:
        if sink.kind == "http":
            _validate_http_sink_target(payload.target)
        sink.target = payload.target
    if payload.hmac_secret is not None:
        sink.hmac_secret = payload.hmac_secret or None
    if payload.config is not None:
        sink.config_json = json.dumps(payload.config)
    if payload.enabled is not None:
        sink.enabled = payload.enabled
    db.commit()
    db.refresh(sink)
    return {"status": "success", "sink": _sink_to_dict(sink)}


@router.delete("/sinks/{sink_id}", response_model=Dict[str, Any])
async def delete_sink(
    sink_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),
    db: DbSession = Depends(get_db),
):
    sink = db.query(AuditSink).filter(AuditSink.id == sink_id).first()
    if sink is None:
        raise HTTPException(status_code=404, detail="sink not found")
    db.delete(sink)
    db.commit()
    return {"status": "success", "message": "sink deleted"}


# ------------------------------------------------------------- deliveries


@router.get("/sinks/{sink_id}/deliveries", response_model=Dict[str, Any])
async def list_deliveries(
    sink_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),
    db: DbSession = Depends(get_db),
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
):
    q = db.query(AuditSinkDelivery).filter(AuditSinkDelivery.sink_id == sink_id)
    if status is not None:
        q = q.filter(AuditSinkDelivery.status == status)
    rows = q.order_by(AuditSinkDelivery.id.desc()).limit(limit).all()
    return {
        "status": "success",
        "deliveries": [
            {
                "id": d.id,
                "event_id": d.event_id,
                "status": d.status,
                "attempts": d.attempts,
                "last_error": d.last_error,
                "next_attempt_at": d.next_attempt_at.isoformat() + "Z"
                if d.next_attempt_at
                else None,
                "delivered_at": d.delivered_at.isoformat() + "Z"
                if d.delivered_at
                else None,
            }
            for d in rows
        ],
    }


@router.post("/deliveries/{delivery_id}/retry", response_model=Dict[str, Any])
async def retry_delivery(
    delivery_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),
    db: DbSession = Depends(get_db),
):
    try:
        d = aes.retry_dead_letter(db, delivery_id)
    except aes.AuditError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"status": "success", "delivery_id": d.id}
