"""API routes for fleet access bindings, roles, grants, and reconcile (PRA-137)."""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field, validator
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role
from ...db.access_models import (
    AccessBinding,
    AccessGrant,
    FleetRole,
    HostUserState,
    RevocationWork,
)
from ...db.models import System, User
from ...db.session import get_db
from ...services import access_binding_service as abs_svc
from ...services import audit_event_service
from ...services import fleet_reconciliation_service as frs
from ...services.access_authorization_service import (
    PermissionDenied,
    active_grant_filter,
    authorize_action,
    cert_principal_for_user,
    is_grant_active,
    resolve_login_resolution,
    scope_query_by_system,
    scoped_system_ids,
    shared_login_conflicts,
    user_can_access_system,
    user_is_tenant_admin,
)
from ...services.privilege_baseline_service import PRIVILEGED_OS_GROUPS

router = APIRouter(redirect_slashes=False)

# PRA-282: Praxis 1.0 ships no standing user-facing privileged escalation. The
# fleet-role API refuses raw sudoers authoring and privileged OS groups so a role
# can never (re)introduce a per-user sudo/root path. Privileged host work is done
# by named Praxis automation; interactive root is out-of-band under the ops
# runbook.
_RAW_SUDOERS_REJECTED = (
    "Raw sudoers authoring is not available in Praxis 1.0. Privileged host work is "
    "performed by named Praxis automation; interactive root is managed out-of-band "
    "under the ops runbook."
)
_ACTIVE_REVOCATION_WORK_STATUSES = ("pending", "error", "manual")


def _reject_raw_sudoers(v):  # noqa: N805
    if v is not None and str(v).strip():
        raise ValueError(_RAW_SUDOERS_REJECTED)
    return v


def _reject_privileged_groups(v):  # noqa: N805
    if v:
        bad = sorted(
            {g for g in v if isinstance(g, str) and g.lower() in PRIVILEGED_OS_GROUPS}
        )
        if bad:
            raise ValueError(
                "Privileged OS groups are not permitted for fleet roles in Praxis "
                f"1.0: {', '.join(bad)}. These confer standing sudo/root; privileged "
                "host work is done by named Praxis automation, not user accounts."
            )
    return v


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class FleetRoleCreate(BaseModel):
    name: str = Field(..., max_length=100)
    description: Optional[str] = None
    login_mode: str = Field("per_user", pattern="^(per_user|role_account)$")
    role_account_name: Optional[str] = Field(None, max_length=100)
    allowed_actions: List[str] = Field(default_factory=list)
    session_requires_approval: bool = False
    totp_required: bool = False
    idle_timeout_s: int = Field(900, ge=60, le=86400)
    max_session_s: int = Field(3600, ge=60, le=86400)
    os_groups: List[str] = Field(default_factory=list)
    # PRA-282: accepted for backward compatibility but must be null/empty; a
    # non-empty value is rejected (raw sudoers authoring is removed for 1.0).
    sudoers_snippet: Optional[str] = None

    @validator("role_account_name", always=True)
    def _check_role_account_name(v, values):  # noqa: N805
        mode = values.get("login_mode")
        if mode == "role_account" and not v:
            raise ValueError("role_account_name required when login_mode=role_account")
        if mode == "per_user" and v:
            raise ValueError("role_account_name must be null when login_mode=per_user")
        return v

    _no_raw_sudoers = validator("sudoers_snippet", allow_reuse=True)(
        _reject_raw_sudoers
    )
    _no_privileged_groups = validator("os_groups", allow_reuse=True)(
        _reject_privileged_groups
    )


class FleetRoleUpdate(BaseModel):
    description: Optional[str] = None
    allowed_actions: Optional[List[str]] = None
    session_requires_approval: Optional[bool] = None
    totp_required: Optional[bool] = None
    idle_timeout_s: Optional[int] = Field(None, ge=60, le=86400)
    max_session_s: Optional[int] = Field(None, ge=60, le=86400)
    os_groups: Optional[List[str]] = None
    # PRA-282: accepted for backward compatibility but must be null/empty.
    sudoers_snippet: Optional[str] = None

    _no_raw_sudoers = validator("sudoers_snippet", allow_reuse=True)(
        _reject_raw_sudoers
    )
    _no_privileged_groups = validator("os_groups", allow_reuse=True)(
        _reject_privileged_groups
    )


class AccessBindingCreate(BaseModel):
    fleet_role_id: int
    subject_user_id: Optional[int] = None
    subject_app_role_id: Optional[int] = None
    scope_group_id: Optional[int] = None
    scope_smart_group_id: Optional[int] = None
    enabled: bool = True
    expires_at: Optional[datetime] = None

    @validator("subject_app_role_id", always=True)
    def _check_subject_xor(v, values):  # noqa: N805
        user_set = values.get("subject_user_id") is not None
        role_set = v is not None
        if user_set == role_set:
            raise ValueError(
                "exactly one of subject_user_id / subject_app_role_id must be set"
            )
        return v

    @validator("scope_smart_group_id", always=True)
    def _check_scope_xor(v, values):  # noqa: N805
        group_set = values.get("scope_group_id") is not None
        sg_set = v is not None
        if group_set == sg_set:
            raise ValueError(
                "exactly one of scope_group_id / scope_smart_group_id must be set"
            )
        return v


class AccessBindingUpdate(BaseModel):
    enabled: Optional[bool] = None
    expires_at: Optional[datetime] = None
    fleet_role_id: Optional[int] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


def _role_to_dict(r: FleetRole) -> Dict[str, Any]:
    return {
        "id": r.id,
        "name": r.name,
        "description": r.description,
        "login_mode": r.login_mode,
        "role_account_name": r.role_account_name,
        "allowed_actions": json.loads(r.allowed_actions_json or "[]"),
        "session_requires_approval": r.session_requires_approval,
        "totp_required": r.totp_required,
        "idle_timeout_s": r.idle_timeout_s,
        "max_session_s": r.max_session_s,
        "os_groups": json.loads(r.os_groups_json or "[]"),
        "sudoers_snippet": r.sudoers_snippet,
        "is_builtin": r.is_builtin,
        "created_at": _iso(r.created_at),
        "updated_at": _iso(r.updated_at),
    }


def _binding_to_dict(b: AccessBinding) -> Dict[str, Any]:
    return {
        "id": b.id,
        "fleet_role_id": b.fleet_role_id,
        "subject_user_id": b.subject_user_id,
        "subject_app_role_id": b.subject_app_role_id,
        "scope_group_id": b.scope_group_id,
        "scope_smart_group_id": b.scope_smart_group_id,
        "enabled": b.enabled,
        "expires_at": _iso(b.expires_at),
        "created_by": b.created_by,
        "created_at": _iso(b.created_at),
        "updated_at": _iso(b.updated_at),
    }


def _grant_to_dict(g: AccessGrant) -> Dict[str, Any]:
    return {
        "id": g.id,
        "user_id": g.user_id,
        "system_id": g.system_id,
        "fleet_role_id": g.fleet_role_id,
        "login": g.login,
        "via_binding_id": g.via_binding_id,
        "is_implicit_admin": g.is_implicit_admin,
        # PRA-284: effective expiry (NULL = never expires) for operator visibility.
        "expires_at": _iso(g.expires_at),
    }


def _host_user_to_dict(h: HostUserState) -> Dict[str, Any]:
    return {
        "id": h.id,
        "system_id": h.system_id,
        "login": h.login,
        "mode": h.mode,
        "state": h.state,
        "last_error": h.last_error,
        "last_reconciled_at": _iso(h.last_reconciled_at),
        "home_archive_path": h.home_archive_path,
    }


# ---------------------------------------------------------------------------
# Fleet roles
# ---------------------------------------------------------------------------


@router.get("/roles", response_model=Dict[str, Any])
def list_fleet_roles(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    roles = db.query(FleetRole).order_by(FleetRole.id.asc()).all()
    return {"status": "success", "roles": [_role_to_dict(r) for r in roles]}


@router.get("/roles/{role_id}", response_model=Dict[str, Any])
def get_fleet_role(
    role_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    role = db.query(FleetRole).filter(FleetRole.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Fleet role not found")
    return {"status": "success", "role": _role_to_dict(role)}


@router.post("/roles", response_model=Dict[str, Any])
def create_fleet_role(
    payload: FleetRoleCreate,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    if db.query(FleetRole).filter(FleetRole.name == payload.name).first():
        raise HTTPException(status_code=400, detail="Fleet role name already in use")
    role = FleetRole(
        name=payload.name,
        description=payload.description,
        login_mode=payload.login_mode,
        role_account_name=payload.role_account_name,
        allowed_actions_json=json.dumps(payload.allowed_actions),
        session_requires_approval=payload.session_requires_approval,
        totp_required=payload.totp_required,
        idle_timeout_s=payload.idle_timeout_s,
        max_session_s=payload.max_session_s,
        os_groups_json=json.dumps(payload.os_groups),
        # PRA-282: fleet roles never carry a raw sudoers snippet in 1.0. The
        # schema already rejects a non-empty value; force NULL regardless.
        sudoers_snippet=None,
        is_builtin=False,
    )
    db.add(role)
    db.commit()
    db.refresh(role)
    return {"status": "success", "role": _role_to_dict(role)}


@router.patch("/roles/{role_id}", response_model=Dict[str, Any])
def update_fleet_role(
    role_id: int = Path(...),
    payload: FleetRoleUpdate = None,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    role = db.query(FleetRole).filter(FleetRole.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Fleet role not found")
    if role.is_builtin:
        raise HTTPException(
            status_code=400, detail="Built-in fleet roles cannot be modified"
        )
    if payload.description is not None:
        role.description = payload.description
    if payload.allowed_actions is not None:
        role.allowed_actions_json = json.dumps(payload.allowed_actions)
    if payload.session_requires_approval is not None:
        role.session_requires_approval = payload.session_requires_approval
    if payload.totp_required is not None:
        role.totp_required = payload.totp_required
    if payload.idle_timeout_s is not None:
        role.idle_timeout_s = payload.idle_timeout_s
    if payload.max_session_s is not None:
        role.max_session_s = payload.max_session_s
    if payload.os_groups is not None:
        role.os_groups_json = json.dumps(payload.os_groups)
    # PRA-282: sudoers_snippet is never writable via the API (the schema rejects a
    # non-empty value); it stays NULL for all 1.0 roles.
    db.commit()
    db.refresh(role)
    return {"status": "success", "role": _role_to_dict(role)}


@router.delete("/roles/{role_id}", response_model=Dict[str, Any])
def delete_fleet_role(
    role_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    role = db.query(FleetRole).filter(FleetRole.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Fleet role not found")
    if role.is_builtin:
        raise HTTPException(
            status_code=400, detail="Built-in fleet roles cannot be deleted"
        )
    in_use = (
        db.query(AccessBinding).filter(AccessBinding.fleet_role_id == role_id).count()
    )
    if in_use > 0:
        raise HTTPException(
            status_code=400,
            detail=f"Role is in use by {in_use} bindings; remove them first",
        )
    db.delete(role)
    db.commit()
    return {"status": "success", "message": f"Fleet role '{role.name}' deleted"}


# ---------------------------------------------------------------------------
# Access bindings
# ---------------------------------------------------------------------------


@router.get("/bindings", response_model=Dict[str, Any])
def list_access_bindings(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    subject_user_id: Optional[int] = Query(None),
    fleet_role_id: Optional[int] = Query(None),
    enabled_only: bool = Query(False),
):
    bindings = abs_svc.list_bindings(
        db,
        subject_user_id=subject_user_id,
        fleet_role_id=fleet_role_id,
        enabled_only=enabled_only,
    )
    return {
        "status": "success",
        "bindings": [_binding_to_dict(b) for b in bindings],
    }


@router.post("/bindings", response_model=Dict[str, Any])
def create_access_binding(
    payload: AccessBindingCreate,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    try:
        binding = abs_svc.create_binding(
            db,
            fleet_role_id=payload.fleet_role_id,
            subject_user_id=payload.subject_user_id,
            subject_app_role_id=payload.subject_app_role_id,
            scope_group_id=payload.scope_group_id,
            scope_smart_group_id=payload.scope_smart_group_id,
            enabled=payload.enabled,
            expires_at=payload.expires_at,
            created_by=current_user.id,
        )
    except abs_svc.BindingValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "success", "binding": _binding_to_dict(binding)}


@router.patch("/bindings/{binding_id}", response_model=Dict[str, Any])
def update_access_binding(
    binding_id: int = Path(...),
    payload: AccessBindingUpdate = None,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    try:
        binding = abs_svc.update_binding(
            db,
            binding_id,
            enabled=payload.enabled,
            expires_at=payload.expires_at,
            fleet_role_id=payload.fleet_role_id,
        )
    except abs_svc.BindingValidationError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"status": "success", "binding": _binding_to_dict(binding)}


@router.delete("/bindings/{binding_id}", response_model=Dict[str, Any])
def delete_access_binding(
    binding_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    if not abs_svc.delete_binding(db, binding_id):
        raise HTTPException(status_code=404, detail="Binding not found")
    return {"status": "success", "message": "Binding deleted"}


# ---------------------------------------------------------------------------
# Grants
# ---------------------------------------------------------------------------


@router.get("/grants", response_model=Dict[str, Any])
def list_grants(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    user_id: Optional[int] = Query(None),
    system_id: Optional[int] = Query(None),
):
    # PRA-281: AccessGrant.system_id is host-derived. An explicit out-of-scope
    # system_id filter is a non-disclosing 404; rows are otherwise restricted to
    # the caller's fleet scope so no hidden grant (user_id / fleet_role_id /
    # login / binding id / implicit-admin flag / system id) leaks. A user_id
    # filter still obeys the system scope; empty scope returns no grants.
    scope = scoped_system_ids(db, current_user)
    if system_id is not None and scope is not None and system_id not in scope:
        raise HTTPException(status_code=404, detail="System not found")
    q = db.query(AccessGrant)
    if user_id is not None:
        q = q.filter(AccessGrant.user_id == user_id)
    if system_id is not None:
        q = q.filter(AccessGrant.system_id == system_id)
    q = scope_query_by_system(q, db, current_user, AccessGrant.system_id)
    grants = q.order_by(AccessGrant.system_id.asc(), AccessGrant.user_id.asc()).all()
    return {"status": "success", "grants": [_grant_to_dict(g) for g in grants]}


@router.post("/grants/recompute", response_model=Dict[str, Any])
def recompute_grants_endpoint(
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    # PRA-281: recompute rematerializes the tenant-wide grant set across every
    # binding/system, so a scoped caller cannot run it without effecting
    # out-of-scope grants. Tenant-wide-admin-only, before any recompute.
    if scoped_system_ids(db, current_user) is not None:
        raise HTTPException(
            status_code=403,
            detail="Recomputing grants requires tenant-wide admin access",
        )
    count = abs_svc.recompute_grants(db)
    return {"status": "success", "grant_count": count}


@router.get("/revocations", response_model=Dict[str, Any])
def revocation_status_endpoint(
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """PRA-285: operator view of the access-revocation drain — pending/error/
    completed counts and the per-host detail (system_id, last_error, attempt,
    next_retry_at) for systems still unreconciled, so operators can see which
    hosts are noncompliant/offline. Fleet-wide status is tenant-wide-admin-only."""
    from ...services import revocation_service

    if scoped_system_ids(db, current_user) is not None:
        raise HTTPException(
            status_code=403,
            detail="Revocation status requires tenant-wide admin access",
        )
    return {"status": "success", **revocation_service.revocation_status(db)}


@router.get("/login-conflicts", response_model=Dict[str, Any])
def login_conflicts_endpoint(
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """PRA-287: operator view of shared-login compatibility conflicts. A conflict
    means two active grants resolve to the same ``(system, login)`` but require
    incompatible host/account/session policy; Praxis fails such access closed and
    refuses to converge host state until the bindings/roles are fixed. Each entry
    lists ``system_id``, ``login``, the conflicting ``role_names`` and the
    ``differing_fields`` — surfaced BEFORE any host change is applied. Scoped to the
    caller's systems (tenant-wide admins see all)."""
    from ...services import access_authorization_service as authz

    scoped = scoped_system_ids(db, current_user)
    conflicts = authz.shared_login_conflicts(db, system_ids=scoped)
    return {"status": "success", "count": len(conflicts), "conflicts": conflicts}


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------


@router.post("/reconcile", response_model=Dict[str, Any])
def reconcile_all_endpoint(
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Reconcile every Active host. Blocking (fleet-scale completes quickly)."""
    totals = frs.reconcile_all()
    return {"status": "success", **totals}


@router.post("/systems/{system_id}/reconcile", response_model=Dict[str, Any])
def reconcile_one_host_endpoint(
    system_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")
    counts = frs.reconcile_system(db, system_id)
    return {"status": "success", "system_id": system_id, **counts}


@router.get("/systems/{system_id}/host-users", response_model=Dict[str, Any])
def list_host_users_endpoint(
    system_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # PRA-281: a direct out-of-scope (or empty-scope) system id is a
    # non-disclosing 404 — identical to a nonexistent host — before the System
    # or HostUserState (per-host login state) rows are queried.
    if scoped_system_ids(db, current_user) is not None and not user_can_access_system(
        db, current_user, system_id
    ):
        raise HTTPException(status_code=404, detail="System not found")
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")
    rows = (
        db.query(HostUserState)
        .filter(HostUserState.system_id == system_id)
        .order_by(HostUserState.login.asc())
        .all()
    )
    return {
        "status": "success",
        "system_id": system_id,
        "host_users": [_host_user_to_dict(h) for h in rows],
    }


# ---------------------------------------------------------------------------
# Effective-access summary (PRA-303)
#
# A READ-ONLY projection of the CURRENT enforced state for one (user, system):
# what the identity can do right now and why. It calls the SAME production
# authorization/resolution services live auth uses (authorize_action, the shared
# login resolver, cert_principal_for_user, the PRA-284 active-grant filter) — it is
# NOT a separate simulator/policy engine and performs NO recompute, reconcile,
# drain, session/cert mint, or host mutation.
# ---------------------------------------------------------------------------


def _expiry_state(expires_at: Optional[datetime], now: datetime) -> str:
    """PRA-284 semantics: ``expires_at <= now`` is expired; NULL never expires."""
    if expires_at is None:
        return "never_expires"
    return "active" if expires_at > now else "expired"


def _grant_ctx(
    g: AccessGrant, role: Optional[FleetRole], now: datetime
) -> Dict[str, Any]:
    return {
        "grant_id": g.id,
        "fleet_role_id": g.fleet_role_id,
        "fleet_role_name": role.name if role else None,
        "login": g.login,
        "expires_at": _iso(g.expires_at),
        "expiry_state": _expiry_state(g.expires_at, now),
        "is_implicit_admin": bool(g.is_implicit_admin),
    }


def _capability_row(
    db: Session,
    action: str,
    user: User,
    system: System,
    login: Optional[str],
    now: datetime,
) -> Dict[str, Any]:
    """Evaluate one capability through the PRODUCTION ``authorize_action`` and map
    the ``AuthorizationResult`` / ``PermissionDenied`` into a row — never inferred
    from role JSON. ``login`` is threaded exactly as the live call site passes it
    (``session_open`` uses a concrete login; ``command_exec`` / ``file_transfer``
    pass ``None`` unless the caller filtered to a specific login)."""
    cert_principal = cert_principal_for_user(user)
    try:
        res = authorize_action(db, user, system, action, login=login, now=now)
    except PermissionDenied as e:
        return {
            "action": action,
            "requested_login": login,
            "allowed": False,
            "code": e.code,
            "reason": e.reason,
            "login": login,
            "cert_principal": cert_principal,
        }
    return {
        "action": action,
        "requested_login": login,
        "allowed": True,
        "code": None,
        "reason": None,
        "login": res.login,
        "cert_principal": cert_principal,
        "login_mode": res.fleet_role.login_mode,
        "role_account_name": res.fleet_role.role_account_name,
        "fleet_role_id": res.fleet_role.id,
        "fleet_role_name": res.fleet_role.name,
        "requires_approval": res.requires_approval,
        "requires_totp": res.requires_totp,
        "idle_timeout_s": res.idle_timeout_s,
        "max_session_s": res.max_session_s,
        "recording_retention_days": res.recording_retention_days,
    }


def _host_state_ctx(hs: Optional[HostUserState]) -> Dict[str, Any]:
    if hs is None:
        # No ledger row — reconcile has not provisioned this login. Access is not
        # usable on-host until reconcile lands (PRA-285 bounded/visible convergence).
        return {"state": "not_provisioned", "converged": False}
    return {
        "state": hs.state,
        "mode": hs.mode,
        "last_error": hs.last_error,
        "last_reconciled_at": _iso(hs.last_reconciled_at),
        "privilege_reconcile_pending": bool(hs.privilege_reconcile_pending),
        "converged": hs.state == "provisioned" and hs.last_error is None,
    }


def _revocation_ctx(
    db: Session, user_id: int, system_id: int, login: str
) -> Dict[str, Any]:
    """Active PRA-285 revocation-reconcile work for this host/login that touches
    this user (or a user-agnostic system/login sweep). A row means the host is not
    yet fully aligned — never a claim of synchronous offline cleanup."""
    rows = (
        db.query(RevocationWork)
        .filter(
            RevocationWork.system_id == system_id,
            RevocationWork.status.in_(_ACTIVE_REVOCATION_WORK_STATUSES),
            or_(RevocationWork.login == login, RevocationWork.login.is_(None)),
            or_(RevocationWork.user_id == user_id, RevocationWork.user_id.is_(None)),
        )
        .order_by(RevocationWork.id.asc())
        .all()
    )
    return {
        "pending": sum(1 for w in rows if w.status == "pending"),
        "error": sum(1 for w in rows if w.status == "error"),
        "manual": sum(1 for w in rows if w.status == "manual"),
        "items": [
            {
                "id": w.id,
                "reason": w.reason,
                "status": w.status,
                "login": w.login,
                "user_id": w.user_id,
                "attempt_count": w.attempt_count,
                "last_error": w.last_error,
                "next_retry_at": _iso(w.next_retry_at),
            }
            for w in rows
        ],
    }


def _login_detail(
    db: Session, user: User, system: System, login: str, now: datetime
) -> Dict[str, Any]:
    """Per-login detail: the live resolver's verdict (compatible role or PRA-287
    conflict), the participating active grants (plus expired ones as explanatory
    context, never as effective access), host convergence, and revocation work."""
    all_grants = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.user_id == user.id,
            AccessGrant.system_id == system.id,
            AccessGrant.login == login,
        )
        .all()
    )
    role_ids = [g.fleet_role_id for g in all_grants]
    roles = {
        r.id: r
        for r in db.query(FleetRole).filter(FleetRole.id.in_(role_ids or [-1])).all()
    }
    active_ctx: List[Dict[str, Any]] = []
    expired_ctx: List[Dict[str, Any]] = []
    for g in all_grants:
        ctx = _grant_ctx(g, roles.get(g.fleet_role_id), now)
        (active_ctx if is_grant_active(g, now) else expired_ctx).append(ctx)

    resolution = resolve_login_resolution(db, system.id, login, now=now)
    resolved_role = resolution.role

    active_expiries = [
        g.expires_at
        for g in all_grants
        if is_grant_active(g, now) and g.expires_at is not None
    ]
    has_never = any(
        is_grant_active(g, now) and g.expires_at is None for g in all_grants
    )
    if has_never:
        expiry_state = "never_expires"
    elif active_expiries:
        expiry_state = "active"
    elif expired_ctx:
        expiry_state = "expired"
    else:
        expiry_state = "none"

    hs = (
        db.query(HostUserState)
        .filter(HostUserState.system_id == system.id, HostUserState.login == login)
        .first()
    )
    return {
        "login": login,
        "login_mode": resolved_role.login_mode if resolved_role else None,
        "role_account_name": resolved_role.role_account_name if resolved_role else None,
        "resolved_fleet_role_id": resolved_role.id if resolved_role else None,
        "resolved_fleet_role_name": resolved_role.name if resolved_role else None,
        "conflict": resolution.conflict,
        "active_grants": active_ctx,
        "expired_grants": expired_ctx,
        "expiry_state": expiry_state,
        "nearest_active_expiry": _iso(min(active_expiries))
        if active_expiries
        else None,
        "host_state": _host_state_ctx(hs),
        "revocation": _revocation_ctx(db, user.id, system.id, login),
    }


def _overall_expiry(
    db: Session, user: User, system: System, now: datetime
) -> Dict[str, Any]:
    grants = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.user_id == user.id,
            AccessGrant.system_id == system.id,
            active_grant_filter(now),
        )
        .all()
    )
    if not grants:
        return {"overall_state": "none", "nearest_active_expiry": None}
    dated = [g.expires_at for g in grants if g.expires_at is not None]
    if any(g.expires_at is None for g in grants):
        return {
            "overall_state": "never_expires",
            "nearest_active_expiry": _iso(min(dated)) if dated else None,
        }
    return {"overall_state": "active", "nearest_active_expiry": _iso(min(dated))}


def build_effective_access_summary(
    db: Session,
    target: User,
    system: System,
    *,
    login: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Assemble the read-only current-state summary for ``(target, system)``.

    Every allow/deny verdict comes from ``authorize_action`` and the shared login
    resolver — this function only projects their output, never re-deriving policy.
    """
    now = now or datetime.utcnow()

    if login is not None:
        logins = [login]
    else:
        rows = (
            db.query(AccessGrant.login)
            .filter(
                AccessGrant.user_id == target.id,
                AccessGrant.system_id == system.id,
                active_grant_filter(now),
            )
            .distinct()
            .all()
        )
        logins = sorted({r[0] for r in rows})

    # Capabilities, evaluated exactly as production enforces each action:
    #   session_open  -> a concrete login (per each of the user's logins);
    #   command_exec / file_transfer -> login=None (their live call sites), or the
    #     filtered login when the operator asked about one specifically.
    capabilities: List[Dict[str, Any]] = []
    for lg in logins:
        capabilities.append(
            _capability_row(db, "session_open", target, system, lg, now)
        )
    action_login = login  # None unless the operator filtered to a specific login
    capabilities.append(
        _capability_row(db, "command_exec", target, system, action_login, now)
    )
    capabilities.append(
        _capability_row(db, "file_transfer", target, system, action_login, now)
    )

    api_allowed = user_can_access_system(db, target, system.id, now=now)

    return {
        "generated_at": _iso(now),
        "identity": {
            "user_id": target.id,
            "username": target.username,
            "is_active": bool(target.is_active),
            "is_tenant_admin": user_is_tenant_admin(target),
            "cert_principal": cert_principal_for_user(target),
        },
        "system": {
            "system_id": system.id,
            "hostname": system.hostname,
            "status": system.status,
        },
        "scoped_api_access": {
            "allowed": api_allowed,
            "code": None if api_allowed else "out_of_scope",
            "reason": None
            if api_allowed
            else "user has no active grant on this system",
        },
        "capabilities": capabilities,
        "logins": [_login_detail(db, target, system, lg, now) for lg in logins],
        "conflicts": shared_login_conflicts(db, system_ids=[system.id], now=now),
        "expiry": _overall_expiry(db, target, system, now),
        "notes": [
            "Current effective access only — not a what-if simulation.",
            "Host-operation eligibility is expressed through session_open, "
            "command_exec, and file_transfer; there is no separate live "
            "authorization path in 1.0.",
            "The SSH connection uses the Linux login as the username; the cert "
            "principal is the immutable praxis-user-<id> (PRA-288).",
            "Privileged/root access is out-of-band under the ops runbook and is not "
            "represented here.",
        ],
    }


@router.get("/effective-access", response_model=Dict[str, Any])
def effective_access_endpoint(
    user_id: int = Query(...),
    system_id: int = Query(...),
    login: Optional[str] = Query(None),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """PRA-303: read-only effective-access summary for one (user, system). Shows
    what the identity can do right now and why, using the live authorization path.
    Read-only — never recomputes, reconciles, drains, mints, or touches hosts.

    Scoped like the other fleet views: an out-of-scope ``system_id`` is a
    non-disclosing 404 (identical to a nonexistent host) before any row is read, so
    a scoped operator cannot enumerate hidden hosts. The lookup is audited with
    actor/target/system/login and the result shape only — never cert material,
    tokens, secrets, or sudo policy text."""
    if scoped_system_ids(db, current_user) is not None and not user_can_access_system(
        db, current_user, system_id
    ):
        raise HTTPException(status_code=404, detail="System not found")
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    summary = build_effective_access_summary(db, target, system, login=login)

    allowed_count = sum(1 for c in summary["capabilities"] if c["allowed"])
    audit_event_service.emit(
        db,
        action="fleet.effective_access.viewed",
        actor_user_id=current_user.id,
        actor_username=current_user.username,
        target_system_id=system_id,
        target_kind="user",
        target_id=user_id,
        context={
            "login": login,
            "capability_count": len(summary["capabilities"]),
            "allowed_count": allowed_count,
            "scoped_api_access": summary["scoped_api_access"]["allowed"],
            "conflict_count": len(summary["conflicts"]),
        },
    )
    return {"status": "success", "summary": summary}
