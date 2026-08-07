"""
API routes for command whitelist and validation rule management (PRA-118).
"""

import json
import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, validator
from sqlalchemy.orm import Session

from ...core.auth import require_role
from ...db.models import (
    CommandDistroMapping,
    CommandValidationRule,
    CommandWhitelist,
    Distro,
    User,
)
from ...db.session import get_db
from ...services.system_audit_service import record_audit

router = APIRouter(redirect_slashes=False)

VALID_RISK_LEVELS = ["low", "medium", "high", "critical"]
VALID_CATEGORIES = [
    "package_management",
    "system_info",
    "file_operations",
    "network",
    "service_management",
    "monitoring",
    "security",
    "custom",
]
VALID_SEVERITIES = ["info", "warning", "error", "critical"]
VALID_VALIDATION_TYPES = ["pattern", "blacklist", "parameter_check"]


# ---------- Pydantic schemas ----------


class DistroMappingIn(BaseModel):
    distro_id: int
    distro_version_pattern: Optional[str] = None
    command_override: Optional[str] = None
    is_supported: bool = True
    notes: Optional[str] = None


class WhitelistCreateIn(BaseModel):
    name: str
    description: Optional[str] = None
    command_pattern: str
    is_regex: bool = False
    risk_level: str
    category: str
    requires_sudo: bool = False
    requires_approval: bool = False
    required_approvals: int = 1
    timeout_seconds: int = 30
    distro_mappings: Optional[List[DistroMappingIn]] = None

    @validator("risk_level")
    def validate_risk_level(cls, v):
        if v not in VALID_RISK_LEVELS:
            raise ValueError(f"Must be one of: {', '.join(VALID_RISK_LEVELS)}")
        return v

    @validator("category")
    def validate_category(cls, v):
        if v not in VALID_CATEGORIES:
            raise ValueError(f"Must be one of: {', '.join(VALID_CATEGORIES)}")
        return v

    @validator("timeout_seconds")
    def validate_timeout(cls, v):
        if not 1 <= v <= 3600:
            raise ValueError("Timeout must be between 1 and 3600 seconds")
        return v


class WhitelistUpdateIn(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    command_pattern: Optional[str] = None
    is_regex: Optional[bool] = None
    is_active: Optional[bool] = None
    risk_level: Optional[str] = None
    category: Optional[str] = None
    requires_sudo: Optional[bool] = None
    requires_approval: Optional[bool] = None
    required_approvals: Optional[int] = None
    timeout_seconds: Optional[int] = None
    distro_mappings: Optional[List[DistroMappingIn]] = None

    @validator("risk_level")
    def validate_risk_level(cls, v):
        if v is not None and v not in VALID_RISK_LEVELS:
            raise ValueError(f"Must be one of: {', '.join(VALID_RISK_LEVELS)}")
        return v

    @validator("category")
    def validate_category(cls, v):
        if v is not None and v not in VALID_CATEGORIES:
            raise ValueError(f"Must be one of: {', '.join(VALID_CATEGORIES)}")
        return v

    @validator("timeout_seconds")
    def validate_timeout(cls, v):
        if v is not None and not 1 <= v <= 3600:
            raise ValueError("Timeout must be between 1 and 3600 seconds")
        return v


class ValidationRuleCreateIn(BaseModel):
    name: str
    description: Optional[str] = None
    validation_type: str
    pattern: str
    is_regex: bool = False
    severity: str
    error_message: Optional[str] = None

    @validator("validation_type")
    def validate_type(cls, v):
        if v not in VALID_VALIDATION_TYPES:
            raise ValueError(f"Must be one of: {', '.join(VALID_VALIDATION_TYPES)}")
        return v

    @validator("severity")
    def validate_severity(cls, v):
        if v not in VALID_SEVERITIES:
            raise ValueError(f"Must be one of: {', '.join(VALID_SEVERITIES)}")
        return v


class ValidationRuleUpdateIn(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    validation_type: Optional[str] = None
    pattern: Optional[str] = None
    is_regex: Optional[bool] = None
    is_active: Optional[bool] = None
    severity: Optional[str] = None
    error_message: Optional[str] = None

    @validator("validation_type")
    def validate_type(cls, v):
        if v is not None and v not in VALID_VALIDATION_TYPES:
            raise ValueError(f"Must be one of: {', '.join(VALID_VALIDATION_TYPES)}")
        return v

    @validator("severity")
    def validate_severity(cls, v):
        if v is not None and v not in VALID_SEVERITIES:
            raise ValueError(f"Must be one of: {', '.join(VALID_SEVERITIES)}")
        return v


class PatternTestIn(BaseModel):
    command: str


# ---------- Serializers ----------


def _serialize_whitelist(entry: CommandWhitelist) -> Dict[str, Any]:
    mappings = []
    for m in entry.distro_commands:
        mappings.append(
            {
                "id": m.id,
                "distro_id": m.distro_id,
                "distro_name": m.distro.name if m.distro else None,
                "distro_version": m.distro.version if m.distro else None,
                "distro_version_pattern": m.distro_version_pattern,
                "command_override": m.command_override,
                "is_supported": m.is_supported,
                "notes": m.notes,
            }
        )
    return {
        "id": entry.id,
        "name": entry.name,
        "description": entry.description,
        "command_pattern": entry.command_pattern,
        "is_regex": entry.is_regex,
        "is_active": entry.is_active,
        "risk_level": entry.risk_level,
        "category": entry.category,
        "requires_sudo": entry.requires_sudo,
        "requires_approval": entry.requires_approval,
        "required_approvals": entry.required_approvals or 1,
        "timeout_seconds": entry.timeout_seconds,
        "created_by": entry.created_by,
        "created_at": entry.created_at.isoformat() + "Z" if entry.created_at else None,
        "updated_at": entry.updated_at.isoformat() + "Z" if entry.updated_at else None,
        "distro_mappings": mappings,
    }


def _serialize_rule(rule: CommandValidationRule) -> Dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "validation_type": rule.validation_type,
        "pattern": rule.pattern,
        "is_regex": rule.is_regex,
        "is_active": rule.is_active,
        "severity": rule.severity,
        "error_message": rule.error_message,
        "created_by": rule.created_by,
        "created_at": rule.created_at.isoformat() + "Z" if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() + "Z" if rule.updated_at else None,
    }


# ---------- Whitelist CRUD ----------


@router.get("/whitelist", response_model=Dict[str, Any])
async def list_whitelist(
    category: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """List all command whitelist entries with optional filters."""
    query = db.query(CommandWhitelist)
    if category:
        query = query.filter(CommandWhitelist.category == category)
    if risk_level:
        query = query.filter(CommandWhitelist.risk_level == risk_level)
    if is_active is not None:
        query = query.filter(CommandWhitelist.is_active == is_active)
    entries = query.order_by(CommandWhitelist.category, CommandWhitelist.name).all()
    return {"entries": [_serialize_whitelist(e) for e in entries]}


@router.post("/whitelist", response_model=Dict[str, Any], status_code=201)
async def create_whitelist_entry(
    payload: WhitelistCreateIn,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Create a new whitelist entry."""
    entry = CommandWhitelist(
        name=payload.name,
        description=payload.description,
        command_pattern=payload.command_pattern,
        is_regex=payload.is_regex,
        risk_level=payload.risk_level,
        category=payload.category,
        requires_sudo=payload.requires_sudo,
        requires_approval=payload.requires_approval,
        required_approvals=payload.required_approvals or 1,
        timeout_seconds=payload.timeout_seconds,
        created_by=current_user.id,
    )
    db.add(entry)
    db.flush()

    if payload.distro_mappings:
        for m in payload.distro_mappings:
            db.add(
                CommandDistroMapping(
                    command_id=entry.id,
                    distro_id=m.distro_id,
                    distro_version_pattern=m.distro_version_pattern,
                    command_override=m.command_override,
                    is_supported=m.is_supported,
                    notes=m.notes,
                )
            )

    record_audit(
        db,
        system_id=None,
        user_id=current_user.id,
        operation="create",
        audit_type="command_whitelist",
        new_value={"name": payload.name, "pattern": payload.command_pattern},
    )
    db.commit()
    db.refresh(entry)
    return _serialize_whitelist(entry)


@router.put("/whitelist/{entry_id}", response_model=Dict[str, Any])
async def update_whitelist_entry(
    payload: WhitelistUpdateIn,
    entry_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Update a whitelist entry."""
    entry = db.query(CommandWhitelist).filter(CommandWhitelist.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Whitelist entry not found")

    old_snapshot = {"name": entry.name, "pattern": entry.command_pattern}
    update_data = payload.dict(exclude_unset=True, exclude={"distro_mappings"})
    for field, value in update_data.items():
        setattr(entry, field, value)

    if payload.distro_mappings is not None:
        # Replace all distro mappings
        db.query(CommandDistroMapping).filter(
            CommandDistroMapping.command_id == entry_id
        ).delete()
        for m in payload.distro_mappings:
            db.add(
                CommandDistroMapping(
                    command_id=entry_id,
                    distro_id=m.distro_id,
                    distro_version_pattern=m.distro_version_pattern,
                    command_override=m.command_override,
                    is_supported=m.is_supported,
                    notes=m.notes,
                )
            )

    record_audit(
        db,
        system_id=None,
        user_id=current_user.id,
        operation="update",
        audit_type="command_whitelist",
        old_value=old_snapshot,
        new_value={"name": entry.name, "pattern": entry.command_pattern},
    )
    db.commit()
    db.refresh(entry)
    return _serialize_whitelist(entry)


@router.delete("/whitelist/{entry_id}", response_model=Dict[str, Any])
async def delete_whitelist_entry(
    entry_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Delete a whitelist entry."""
    entry = db.query(CommandWhitelist).filter(CommandWhitelist.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Whitelist entry not found")

    record_audit(
        db,
        system_id=None,
        user_id=current_user.id,
        operation="delete",
        audit_type="command_whitelist",
        old_value={"name": entry.name, "pattern": entry.command_pattern},
    )
    db.delete(entry)
    db.commit()
    return {"status": "deleted", "id": entry_id}


# ---------- Validation Rule CRUD ----------


@router.get("/validation-rules", response_model=Dict[str, Any])
async def list_validation_rules(
    severity: Optional[str] = Query(None),
    validation_type: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """List all validation rules with optional filters."""
    query = db.query(CommandValidationRule)
    if severity:
        query = query.filter(CommandValidationRule.severity == severity)
    if validation_type:
        query = query.filter(CommandValidationRule.validation_type == validation_type)
    if is_active is not None:
        query = query.filter(CommandValidationRule.is_active == is_active)
    rules = query.order_by(
        CommandValidationRule.severity.desc(), CommandValidationRule.name
    ).all()
    return {"rules": [_serialize_rule(r) for r in rules]}


@router.post("/validation-rules", response_model=Dict[str, Any], status_code=201)
async def create_validation_rule(
    payload: ValidationRuleCreateIn,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Create a new validation rule."""
    rule = CommandValidationRule(
        name=payload.name,
        description=payload.description,
        validation_type=payload.validation_type,
        pattern=payload.pattern,
        is_regex=payload.is_regex,
        severity=payload.severity,
        error_message=payload.error_message,
        created_by=current_user.id,
    )
    db.add(rule)

    record_audit(
        db,
        system_id=None,
        user_id=current_user.id,
        operation="create",
        audit_type="validation_rule",
        new_value={"name": payload.name, "pattern": payload.pattern},
    )
    db.commit()
    db.refresh(rule)
    return _serialize_rule(rule)


@router.put("/validation-rules/{rule_id}", response_model=Dict[str, Any])
async def update_validation_rule(
    payload: ValidationRuleUpdateIn,
    rule_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Update a validation rule."""
    rule = (
        db.query(CommandValidationRule)
        .filter(CommandValidationRule.id == rule_id)
        .first()
    )
    if not rule:
        raise HTTPException(status_code=404, detail="Validation rule not found")

    old_snapshot = {"name": rule.name, "pattern": rule.pattern}
    for field, value in payload.dict(exclude_unset=True).items():
        setattr(rule, field, value)

    record_audit(
        db,
        system_id=None,
        user_id=current_user.id,
        operation="update",
        audit_type="validation_rule",
        old_value=old_snapshot,
        new_value={"name": rule.name, "pattern": rule.pattern},
    )
    db.commit()
    db.refresh(rule)
    return _serialize_rule(rule)


@router.delete("/validation-rules/{rule_id}", response_model=Dict[str, Any])
async def delete_validation_rule(
    rule_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Delete a validation rule."""
    rule = (
        db.query(CommandValidationRule)
        .filter(CommandValidationRule.id == rule_id)
        .first()
    )
    if not rule:
        raise HTTPException(status_code=404, detail="Validation rule not found")

    record_audit(
        db,
        system_id=None,
        user_id=current_user.id,
        operation="delete",
        audit_type="validation_rule",
        old_value={"name": rule.name, "pattern": rule.pattern},
    )
    db.delete(rule)
    db.commit()
    return {"status": "deleted", "id": rule_id}


# ---------- Pattern tester ----------


def _matches_pattern(command: str, pattern: str, is_regex: bool) -> bool:
    """Check if command matches a pattern (mirrors validation service logic)."""
    if is_regex:
        try:
            return bool(re.search(pattern, command, re.IGNORECASE))
        except re.error:
            return pattern.lower() in command.lower()
    pattern_regex = pattern.replace("*", ".*").replace("?", ".")
    try:
        return bool(re.match(f"^{pattern_regex}$", command, re.IGNORECASE))
    except re.error:
        return pattern.lower() in command.lower()


@router.post("/test-pattern", response_model=Dict[str, Any])
async def test_pattern(
    payload: PatternTestIn,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Test a command against all active whitelist entries and validation rules."""
    command = payload.command.strip()

    whitelist_matches = []
    for entry in (
        db.query(CommandWhitelist).filter(CommandWhitelist.is_active.is_(True)).all()
    ):
        if _matches_pattern(command, entry.command_pattern, entry.is_regex):
            whitelist_matches.append(
                {
                    "id": entry.id,
                    "name": entry.name,
                    "command_pattern": entry.command_pattern,
                    "risk_level": entry.risk_level,
                    "category": entry.category,
                }
            )

    rule_matches = []
    for rule in (
        db.query(CommandValidationRule)
        .filter(CommandValidationRule.is_active.is_(True))
        .all()
    ):
        if _matches_pattern(command, rule.pattern, rule.is_regex):
            rule_matches.append(
                {
                    "id": rule.id,
                    "name": rule.name,
                    "pattern": rule.pattern,
                    "severity": rule.severity,
                    "validation_type": rule.validation_type,
                }
            )

    allowed = len(whitelist_matches) > 0
    blocked_by_rule = any(r["severity"] in ("critical", "error") for r in rule_matches)

    return {
        "command": command,
        "allowed": allowed and not blocked_by_rule,
        "whitelist_matches": whitelist_matches,
        "rule_matches": rule_matches,
    }


# ---------- Distros list (for the frontend form) ----------


@router.get("/distros", response_model=Dict[str, Any])
async def list_distros(
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """List all available distributions for distro mapping."""
    distros = db.query(Distro).order_by(Distro.name, Distro.version).all()
    return {
        "distros": [{"id": d.id, "name": d.name, "version": d.version} for d in distros]
    }
