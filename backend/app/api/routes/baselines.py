"""API routes for drift baselines (PRA-127)."""

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role, require_system_access
from ...db.models import Baseline, BaselineCheck, System, User
from ...db.session import SessionLocal, get_db
from ...services import drift_service
from ...services.access_authorization_service import scoped_system_ids

router = APIRouter(redirect_slashes=False)


class BaselineCreate(BaseModel):
    name: str = Field(..., max_length=100)
    description: Optional[str] = None
    scope_smart_group_id: Optional[int] = None
    rules_json: Dict[str, Any]
    enabled: bool = True
    schedule_interval_hours: int = Field(24, ge=1, le=24 * 30)


class BaselineUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = None
    scope_smart_group_id: Optional[int] = None
    clear_scope: Optional[bool] = False
    rules_json: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None
    schedule_interval_hours: Optional[int] = Field(None, ge=1, le=24 * 30)


def _utc_iso(dt):
    return dt.isoformat() + "Z" if dt else None


def _to_dict(
    b: Baseline, db: Session, scope_system_ids: Optional[set] = None
) -> Dict[str, Any]:
    # latest-per-system counts. PRA-281: for a scoped caller, only count checks
    # for systems in scope (a fully-visible baseline's checks are all in-scope,
    # but historical rows for systems that left the scope are excluded).
    count_q = db.query(BaselineCheck.status, func.count(BaselineCheck.id)).filter(
        BaselineCheck.baseline_id == b.id
    )
    if scope_system_ids is not None:
        count_q = count_q.filter(BaselineCheck.system_id.in_(scope_system_ids))
    rows = count_q.group_by(BaselineCheck.status).all()
    status_counts = {"compliant": 0, "drifted": 0, "error": 0}
    for s, c in rows:
        if s in status_counts:
            status_counts[s] = c
    return {
        "id": b.id,
        "name": b.name,
        "description": b.description,
        "scope_smart_group_id": b.scope_smart_group_id,
        "rules_json": json.loads(b.rules_json) if b.rules_json else {},
        "enabled": b.enabled,
        "schedule_interval_hours": b.schedule_interval_hours,
        "last_run_at": _utc_iso(b.last_run_at),
        "created_at": _utc_iso(b.created_at),
        "updated_at": _utc_iso(b.updated_at),
        "status_counts": status_counts,
    }


@router.get("", response_model=Dict[str, Any])
async def list_baselines(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    baselines = db.query(Baseline).order_by(Baseline.id.desc()).all()
    # PRA-281: a scoped caller only sees baselines whose target set is entirely in
    # scope; their status_counts are scoped too. Admin (scope None) sees all with
    # global counts.
    scope = scoped_system_ids(db, current_user)
    if scope is not None:
        baselines = [
            b
            for b in baselines
            if drift_service.baseline_visible_to_scope(db, b, scope)
        ]
    return {
        "status": "success",
        "baselines": [_to_dict(b, db, scope_system_ids=scope) for b in baselines],
    }


@router.post("", response_model=Dict[str, Any])
async def create_baseline(
    payload: BaselineCreate,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    try:
        drift_service.validate_rules(payload.rules_json)
    except drift_service.BaselineRuleError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # PRA-281: a scoped caller may only create a baseline whose resolved target
    # set is non-empty and entirely in scope, with a generic (non-disclosing)
    # message. An UNSCOPED baseline is tenant-wide and auto-widens as new active
    # systems appear, so it is rejected outright for scoped callers regardless of
    # whether their current grants happen to cover every active system — only a
    # tenant-wide admin (scope is None) may create one.
    scope = scoped_system_ids(db, current_user)
    if scope is not None and (
        payload.scope_smart_group_id is None
        or not drift_service.baseline_visible_to_scope(
            db, Baseline(scope_smart_group_id=payload.scope_smart_group_id), scope
        )
    ):
        raise HTTPException(
            status_code=400,
            detail="baseline scope must resolve to systems within your access scope",
        )
    if db.query(Baseline).filter(Baseline.name == payload.name).first():
        raise HTTPException(status_code=400, detail="Name already in use")
    b = Baseline(
        name=payload.name,
        description=payload.description,
        scope_smart_group_id=payload.scope_smart_group_id,
        rules_json=json.dumps(payload.rules_json),
        enabled=payload.enabled,
        schedule_interval_hours=payload.schedule_interval_hours,
        created_by=current_user.id,
    )
    db.add(b)
    db.commit()
    db.refresh(b)
    return {"status": "success", "baseline": _to_dict(b, db, scope_system_ids=scope)}


@router.put("/{baseline_id}", response_model=Dict[str, Any])
async def update_baseline(
    baseline_id: int = Path(...),
    payload: BaselineUpdate = None,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    b = db.query(Baseline).filter(Baseline.id == baseline_id).first()
    if not b:
        raise HTTPException(status_code=404, detail="Baseline not found")
    # PRA-281: a scoped caller must (a) already be able to see this baseline
    # (else non-disclosing 404) and (b) not repoint it to a target set that is
    # not entirely in scope (rejects clear_scope / widening to tenant-wide /
    # out-of-scope or mixed smart groups).
    scope = scoped_system_ids(db, current_user)
    if scope is not None:
        if not drift_service.baseline_visible_to_scope(db, b, scope):
            raise HTTPException(status_code=404, detail="Baseline not found")
        if payload.clear_scope:
            eff_sg = None
        elif payload.scope_smart_group_id is not None:
            eff_sg = payload.scope_smart_group_id
        else:
            eff_sg = b.scope_smart_group_id
        # An effective UNSCOPED result (clearing scope, or retaining/setting a
        # tenant-wide baseline) auto-widens as new active systems appear, so a
        # scoped caller may never land there — only a tenant-wide admin can.
        if eff_sg is None or not drift_service.baseline_visible_to_scope(
            db, Baseline(scope_smart_group_id=eff_sg), scope
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    "baseline scope must resolve to systems within your access scope"
                ),
            )
    if payload.name is not None:
        if (
            db.query(Baseline)
            .filter(Baseline.name == payload.name, Baseline.id != baseline_id)
            .first()
        ):
            raise HTTPException(status_code=400, detail="Name already in use")
        b.name = payload.name
    if payload.description is not None:
        b.description = payload.description
    if payload.clear_scope:
        b.scope_smart_group_id = None
    elif payload.scope_smart_group_id is not None:
        b.scope_smart_group_id = payload.scope_smart_group_id
    if payload.rules_json is not None:
        try:
            drift_service.validate_rules(payload.rules_json)
        except drift_service.BaselineRuleError as e:
            raise HTTPException(status_code=400, detail=str(e))
        b.rules_json = json.dumps(payload.rules_json)
    if payload.enabled is not None:
        b.enabled = payload.enabled
    if payload.schedule_interval_hours is not None:
        b.schedule_interval_hours = payload.schedule_interval_hours
    db.commit()
    db.refresh(b)
    return {"status": "success", "baseline": _to_dict(b, db, scope_system_ids=scope)}


@router.delete("/{baseline_id}", response_model=Dict[str, Any])
async def delete_baseline(
    baseline_id: int = Path(...),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    b = db.query(Baseline).filter(Baseline.id == baseline_id).first()
    if not b:
        raise HTTPException(status_code=404, detail="Baseline not found")
    # PRA-281: non-disclosing 404 for a baseline whose target set is not entirely
    # in the caller's scope (out-of-scope-only, mixed, or tenant-wide).
    scope = scoped_system_ids(db, current_user)
    if scope is not None and not drift_service.baseline_visible_to_scope(db, b, scope):
        raise HTTPException(status_code=404, detail="Baseline not found")
    db.delete(b)
    db.commit()
    return {"status": "success", "message": f"Baseline '{b.name}' deleted"}


def _run_in_background(baseline_id: int):
    db = SessionLocal()
    try:
        drift_service.run_baseline(db, baseline_id)
    finally:
        db.close()


@router.post("/{baseline_id}/run", response_model=Dict[str, Any])
async def run_now(
    baseline_id: int,
    background: BackgroundTasks,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    b = db.query(Baseline).filter(Baseline.id == baseline_id).first()
    if not b:
        raise HTTPException(status_code=404, detail="Baseline not found")
    # PRA-281: a scoped caller may only run a baseline whose target set is entirely
    # in scope (non-disclosing 404 otherwise) — before the background run is
    # queued. The background run itself stays tenant-wide over the baseline's own
    # scope, which is safe because that scope is fully inside the caller's.
    scope = scoped_system_ids(db, current_user)
    if scope is not None and not drift_service.baseline_visible_to_scope(db, b, scope):
        raise HTTPException(status_code=404, detail="Baseline not found")
    background.add_task(_run_in_background, baseline_id)
    return {"status": "queued", "baseline_id": baseline_id}


@router.get("/{baseline_id}/checks", response_model=Dict[str, Any])
async def list_checks(
    baseline_id: int = Path(...),
    latest_only: bool = Query(True),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    b = db.query(Baseline).filter(Baseline.id == baseline_id).first()
    if not b:
        raise HTTPException(status_code=404, detail="Baseline not found")

    # PRA-281: return only check rows for systems in the caller's fleet scope.
    # Admin (scope None) sees all; empty scope yields no rows. The baseline id
    # itself is not treated as fleet inventory here — a missing baseline stays a
    # 404 while an out-of-scope baseline simply yields scoped (possibly empty)
    # checks.
    scope = scoped_system_ids(db, current_user)

    def _scoped(query):
        if scope is None:
            return query
        return query.filter(BaselineCheck.system_id.in_(scope))

    if latest_only:
        sub = (
            db.query(
                BaselineCheck.system_id,
                func.max(BaselineCheck.run_at).label("latest"),
            )
            .filter(BaselineCheck.baseline_id == baseline_id)
            .group_by(BaselineCheck.system_id)
            .subquery()
        )
        rows = (
            _scoped(
                db.query(BaselineCheck)
                .join(
                    sub,
                    (BaselineCheck.system_id == sub.c.system_id)
                    & (BaselineCheck.run_at == sub.c.latest),
                )
                .filter(BaselineCheck.baseline_id == baseline_id)
            )
            .limit(limit)
            .all()
        )
    else:
        rows = (
            _scoped(
                db.query(BaselineCheck)
                .filter(BaselineCheck.baseline_id == baseline_id)
                .order_by(BaselineCheck.run_at.desc())
            )
            .limit(limit)
            .all()
        )

    system_map = {
        s.id: s.hostname
        for s in db.query(System)
        .filter(System.id.in_([r.system_id for r in rows]))
        .all()
    }

    return {
        "status": "success",
        "baseline_id": baseline_id,
        "checks": [
            {
                "id": r.id,
                "system_id": r.system_id,
                "hostname": system_map.get(r.system_id, f"#{r.system_id}"),
                "run_at": _utc_iso(r.run_at),
                "status": r.status,
                "drift_details": (
                    json.loads(r.drift_details_json) if r.drift_details_json else None
                ),
            }
            for r in rows
        ],
    }


@router.get("/-/drift/summary", response_model=Dict[str, Any])
async def drift_summary_endpoint(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # PRA-281: scope the summary to the caller's fleet (admin None → tenant-wide;
    # empty scope → zeroed counts).
    return {
        "status": "success",
        **drift_service.drift_summary(
            db, scope_system_ids=scoped_system_ids(db, current_user)
        ),
    }


@router.get("/-/drift/by-system", response_model=Dict[str, Any])
async def drift_by_system(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return matrix of latest status per (baseline, system)."""
    # PRA-281: baseline column headers stay global (a baseline name is definition
    # metadata, not host inventory — documented in the inventory), but the system
    # ROWS and their cells are restricted to the caller's fleet scope. Admin
    # (scope None) sees all systems; empty scope yields rows: [].
    scope = scoped_system_ids(db, current_user)
    baselines = db.query(Baseline).filter(Baseline.enabled.is_(True)).all()
    if not baselines:
        return {"status": "success", "baselines": [], "rows": []}

    sub = (
        db.query(
            BaselineCheck.baseline_id,
            BaselineCheck.system_id,
            func.max(BaselineCheck.run_at).label("latest"),
        )
        .group_by(BaselineCheck.baseline_id, BaselineCheck.system_id)
        .subquery()
    )
    rows = (
        db.query(BaselineCheck)
        .join(
            sub,
            (BaselineCheck.baseline_id == sub.c.baseline_id)
            & (BaselineCheck.system_id == sub.c.system_id)
            & (BaselineCheck.run_at == sub.c.latest),
        )
        .all()
    )

    systems_q = db.query(System).order_by(System.hostname)
    if scope is not None:
        systems_q = systems_q.filter(System.id.in_(scope))
    systems = systems_q.all()
    sys_map = {s.id: s.hostname for s in systems}

    # Build matrix
    matrix: Dict[int, Dict[int, Dict[str, Any]]] = {}
    for r in rows:
        matrix.setdefault(r.system_id, {})[r.baseline_id] = {
            "status": r.status,
            "run_at": _utc_iso(r.run_at),
            "drift_details": (
                json.loads(r.drift_details_json) if r.drift_details_json else None
            ),
        }

    return {
        "status": "success",
        "baselines": [{"id": b.id, "name": b.name} for b in baselines],
        "rows": [
            {
                "system_id": s.id,
                "hostname": s.hostname,
                "cells": [
                    matrix.get(s.id, {}).get(b.id) or {"status": "unknown"}
                    for b in baselines
                ],
            }
            for s in systems
        ],
    }


@router.get(
    "/-/drift/system/{system_id}",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access())],
)
async def drift_for_system(
    system_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Used by system detail page for compliance badge + drift panel.

    PRA-281: ``require_system_access()`` 404s an out-of-scope system id before any
    baseline check / drift detail is read.
    """
    baselines = db.query(Baseline).filter(Baseline.enabled.is_(True)).all()
    out: List[Dict[str, Any]] = []
    worst = "compliant"
    for b in baselines:
        chk = drift_service.latest_check(db, b.id, system_id)
        if not chk:
            continue
        if chk.status == "drifted":
            worst = "drifted"
        elif chk.status == "error" and worst != "drifted":
            worst = "error"
        out.append(
            {
                "baseline_id": b.id,
                "baseline_name": b.name,
                "status": chk.status,
                "run_at": _utc_iso(chk.run_at),
                "drift_details": (
                    json.loads(chk.drift_details_json)
                    if chk.drift_details_json
                    else None
                ),
            }
        )
    return {
        "status": "success",
        "system_id": system_id,
        "overall": worst if out else "unknown",
        "checks": out,
    }
