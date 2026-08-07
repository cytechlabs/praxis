"""API routes for smart groups (PRA-126)."""

import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role
from ...db.models import SmartGroup, SmartGroupMembership, System, User
from ...db.session import get_db
from ...services import smart_group_service as sg
from ...services.access_authorization_service import scoped_system_ids

router = APIRouter(redirect_slashes=False)


def _member_ids(db: Session, group_id: int) -> set:
    return {
        row[0]
        for row in db.query(SmartGroupMembership.system_id)
        .filter(SmartGroupMembership.smart_group_id == group_id)
        .all()
    }


def _smart_group_visible_to_scope(db: Session, group_id: int, scope) -> bool:
    """PRA-281: a smart group's materialized membership is host-derived. Admin
    (scope ``None``) sees all; a scoped caller may see/operate a smart group only
    when its members are non-empty AND entirely in scope (fail closed for
    empty/mixed/out-of-scope), so member counts/ids never leak fleet structure."""
    if scope is None:
        return True
    members = _member_ids(db, group_id)
    return bool(members) and members.issubset(scope)


def _require_tenant_wide(db: Session, current_user: User) -> None:
    """Smart-group create/update/delete/recompute materialize/maintain GLOBAL
    membership across the whole fleet, so a scoped caller cannot perform them
    without materializing/revealing out-of-scope membership. Restrict to
    tenant-wide admins."""
    if scoped_system_ids(db, current_user) is not None:
        raise HTTPException(
            status_code=403,
            detail="Managing smart groups requires tenant-wide admin access",
        )


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class SmartGroupCreate(BaseModel):
    name: str = Field(..., max_length=100)
    description: Optional[str] = None
    rule_json: Dict[str, Any]
    enabled: bool = True


class SmartGroupUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = None
    rule_json: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


class PreviewBody(BaseModel):
    rule_json: Dict[str, Any]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_iso(dt):
    return dt.isoformat() + "Z" if dt else None


def _to_dict(g: SmartGroup, member_count: int) -> Dict[str, Any]:
    return {
        "id": g.id,
        "name": g.name,
        "description": g.description,
        "rule_json": json.loads(g.rule_json),
        "enabled": g.enabled,
        "member_count": member_count,
        "created_by": g.created_by,
        "created_at": _utc_iso(g.created_at),
        "updated_at": _utc_iso(g.updated_at),
    }


def _count_members(db: Session, group_id: int) -> int:
    return (
        db.query(SmartGroupMembership)
        .filter(SmartGroupMembership.smart_group_id == group_id)
        .count()
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=Dict[str, Any])
async def list_smart_groups(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    groups = db.query(SmartGroup).order_by(SmartGroup.id.desc()).all()
    # PRA-281: scoped callers only see smart groups whose members are entirely in
    # scope (admin sees all); a visible group's member_count is all in-scope.
    scope = scoped_system_ids(db, current_user)
    if scope is not None:
        groups = [g for g in groups if _smart_group_visible_to_scope(db, g.id, scope)]
    return {
        "status": "success",
        "smart_groups": [_to_dict(g, _count_members(db, g.id)) for g in groups],
    }


@router.get("/field-catalog", response_model=Dict[str, Any])
async def field_catalog(current_user: User = Depends(get_current_user)):
    """Return the list of supported fields + op per field for UI builder."""
    catalog = []
    for f in sorted(sg.STRING_FIELDS):
        catalog.append({"field": f, "type": "string", "ops": sorted(sg.STRING_OPS)})
    for f in sorted(sg.ENUM_FIELDS):
        catalog.append({"field": f, "type": "enum", "ops": sorted(sg.ENUM_OPS)})
    for f in sorted(sg.BOOL_FIELDS):
        catalog.append({"field": f, "type": "bool", "ops": sorted(sg.BOOL_OPS)})
    for f in sorted(sg.NUMBER_FIELDS):
        catalog.append({"field": f, "type": "number", "ops": sorted(sg.NUMBER_OPS)})
    return {"status": "success", "catalog": catalog}


@router.post("", response_model=Dict[str, Any])
async def create_smart_group(
    payload: SmartGroupCreate,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    _require_tenant_wide(db, current_user)
    try:
        sg.validate_rule(payload.rule_json)
        sg.validate_rule_against_db(payload.rule_json, db)
    except sg.RuleValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if db.query(SmartGroup).filter(SmartGroup.name == payload.name).first():
        raise HTTPException(status_code=400, detail="Name already in use")

    group = SmartGroup(
        name=payload.name,
        description=payload.description,
        rule_json=json.dumps(payload.rule_json),
        enabled=payload.enabled,
        created_by=current_user.id,
    )
    db.add(group)
    db.commit()
    db.refresh(group)

    count = sg.recompute_membership(db, group.id)
    return {"status": "success", "smart_group": _to_dict(group, count)}


@router.put("/{group_id}", response_model=Dict[str, Any])
async def update_smart_group(
    group_id: int = Path(...),
    payload: SmartGroupUpdate = None,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    _require_tenant_wide(db, current_user)
    group = db.query(SmartGroup).filter(SmartGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Smart group not found")

    if payload.name is not None:
        if (
            db.query(SmartGroup)
            .filter(SmartGroup.name == payload.name, SmartGroup.id != group_id)
            .first()
        ):
            raise HTTPException(status_code=400, detail="Name already in use")
        group.name = payload.name
    if payload.description is not None:
        group.description = payload.description
    if payload.enabled is not None:
        group.enabled = payload.enabled
    rule_changed = False
    if payload.rule_json is not None:
        try:
            sg.validate_rule(payload.rule_json)
            sg.validate_rule_against_db(payload.rule_json, db)
        except sg.RuleValidationError as e:
            raise HTTPException(status_code=400, detail=str(e))
        group.rule_json = json.dumps(payload.rule_json)
        rule_changed = True

    db.commit()
    db.refresh(group)

    if rule_changed or payload.enabled is not None:
        sg.recompute_membership(db, group.id)

    return {
        "status": "success",
        "smart_group": _to_dict(group, _count_members(db, group.id)),
    }


@router.delete("/{group_id}", response_model=Dict[str, Any])
async def delete_smart_group(
    group_id: int = Path(...),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    _require_tenant_wide(db, current_user)
    group = db.query(SmartGroup).filter(SmartGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Smart group not found")
    db.delete(group)
    db.commit()
    return {"status": "success", "message": f"Smart group '{group.name}' deleted"}


@router.get("/{group_id}/members", response_model=Dict[str, Any])
async def list_members(
    group_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    group = db.query(SmartGroup).filter(SmartGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Smart group not found")
    # PRA-281: non-disclosing 404 before any member id/hostname is returned for a
    # smart group not fully in the caller's scope.
    scope = scoped_system_ids(db, current_user)
    if scope is not None and not _smart_group_visible_to_scope(db, group_id, scope):
        raise HTTPException(status_code=404, detail="Smart group not found")

    ids = sg.members(db, group_id)
    systems = db.query(System).filter(System.id.in_(ids)).all() if ids else []
    return {
        "status": "success",
        "group_id": group_id,
        "member_count": len(systems),
        "members": [
            {
                "id": s.id,
                "hostname": s.hostname,
                "ip_address": str(s.ip_address) if s.ip_address else None,
                "status": s.status,
                "group_id": s.group_id,
            }
            for s in systems
        ],
    }


@router.post("/{group_id}/recompute", response_model=Dict[str, Any])
async def recompute(
    group_id: int = Path(...),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    _require_tenant_wide(db, current_user)
    group = db.query(SmartGroup).filter(SmartGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Smart group not found")
    count = sg.recompute_membership(db, group_id)
    return {"status": "success", "member_count": count}


@router.post("/preview", response_model=Dict[str, Any])
async def preview(
    payload: PreviewBody,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=500),
):
    """Evaluate a rule without persisting. Used by UI builder for live preview."""
    try:
        sg.validate_rule(payload.rule_json)
        sg.validate_rule_against_db(payload.rule_json, db)
    except sg.RuleValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        ids = sg.evaluate(payload.rule_json, db)
    except Exception as e:  # pylint: disable=broad-except
        raise HTTPException(status_code=400, detail=f"Rule evaluation error: {e}")

    # PRA-281: evaluate the predicate THROUGH fleet scope — a scoped caller only
    # sees in-scope preview members and an in-scope total, so a predicate that
    # would only match hidden systems cannot reveal them via count/members.
    scope = scoped_system_ids(db, current_user)
    if scope is not None:
        ids = [i for i in ids if i in scope]

    total = len(ids)
    ids = ids[:limit]
    systems = db.query(System).filter(System.id.in_(ids)).all() if ids else []
    return {
        "status": "success",
        "total": total,
        "members": [
            {
                "id": s.id,
                "hostname": s.hostname,
                "status": s.status,
            }
            for s in systems
        ],
    }
