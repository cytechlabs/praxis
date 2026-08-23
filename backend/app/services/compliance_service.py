"""Compliance policy service (PRA-165 slice 1).

Slice 1 implements the substrate only — CRUD for policies and
checks, typed check-definition validation, idempotent starter-pack
seeding, and audit emission. NO probe execution lives here:

* package-shaped checks (``package_installed``, ``package_absent``,
  ``package_version_min``) — runner deferred to PRA-165 Slice 2;
* fact-shaped checks (``fact_equals``, ``fact_present``,
  ``fact_absent``) — runner deferred to PRA-165 Slice 2;
* file-shaped checks (``file_exists``, ``file_sha256``) — runner
  owned by PRA-166;
* command-shaped checks (``command_stdout_contains``,
  ``command_exit_code``) — runner owned by PRA-166.

Read surfaces (the route layer and ``check_read_envelope`` below)
expose each check's ``runner_status`` + ``runner_owner`` explicitly
so consumers can never mistake a stored definition for an
evaluated result.

Audit-row semantics follow ``feedback_safe_emit_session_boundary``:
``safe_emit`` is invoked AFTER the service commits its own
transaction, with no ``db=`` argument so it opens its own
``SessionLocal``.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from ..db.models import CompliancePolicy, CompliancePolicyCheck, User
from . import compliance_labels
from .audit_event_service import safe_emit
from .compliance_starter_pack import STARTER_PACK

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# UTC wire-shape helper — read surfaces must serialize timestamps as
# absolute-UTC ISO 8601 strings ending in ``Z`` (Slice 1 lock; mirrors
# the patch-lifecycle ``utc_iso`` helper). DB stores naive-UTC, so we
# append ``Z`` to naive values and normalize tz-aware to ``...Z``.
#
# Promoted to a public symbol in Slice 3 so the new read schemas,
# summary endpoints, and JSONL/CSV export streams can reuse one
# canonical formatter instead of redefining it per module.
# ---------------------------------------------------------------------------


def utc_iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.isoformat() + "Z"
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Local exception class — mirrors the patch-policy service so route
# layers can map the whole family to HTTP 422 / 404.
# ---------------------------------------------------------------------------


class ComplianceError(ValueError):
    """Raised when a compliance policy/check operation is rejected for
    semantic reasons (slug conflict, unknown check kind, bad
    definition shape, locked built-in delete, etc.).

    Subclasses ``ValueError`` so route layers can map the whole
    family to HTTP 422; messages containing ``"not found"`` are
    re-mapped to 404 at the route boundary.
    """


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

VALID_SEVERITIES: Tuple[str, ...] = ("low", "medium", "high", "critical")

# Runner ownership vocabulary. Surfaces on read payloads so consumers
# can never confuse a stored definition with an evaluated result.
#
# * ``deferred_to_pra165_slice_2`` — package/fact kinds; runner lands
#   in PRA-165 Slice 2 (now implemented; string is the stable wire-
#   shape label that PRA-165's CSV/JSONL export contract pinned).
# * ``deferred_to_pra166`` — file/command kinds; runner owned by
#   PRA-166. The runner shipped in PRA-166 Slice 1; the string
#   intentionally stays ``deferred_to_pra166`` because PRA-165's
#   read/export wire-shape contract pinned this exact value before
#   the runner landed. PRA-166 Slice 3 evaluated renaming to a
#   clearer label (e.g. ``pra166_file_command_runner``) with a
#   compatibility shim in ``evidence_export_row``; a rename would
#   either churn historical evidence rows (the shim returns the
#   legacy string anyway, so the wire never changes) or break
#   external consumers (no shim) — net value is purely cosmetic
#   while the legacy string remains operationally accurate as an
#   identifier. The label is pinned by a test in
#   ``test_pra166_compliance_probe_runner.py`` so an accidental
#   rename trips a clear failure pointing back here.
RUNNER_OWNER_SLICE_2 = "deferred_to_pra165_slice_2"
RUNNER_OWNER_PRA166 = "deferred_to_pra166"

# In Slice 1 nothing has been executed. The single runner-status
# string makes that explicit on read surfaces.
RUNNER_STATUS_NOT_IMPLEMENTED = "runner_not_implemented_in_slice_1"


# Per-kind metadata. Each entry says who validates the definition
# JSON and which runner will eventually execute it. ``validator`` is
# a callable that raises ``ComplianceError`` on bad shape and
# returns a normalized definition dict.
def _err(msg: str) -> ComplianceError:
    return ComplianceError(msg)


def _require_str(value: Any, field: str, max_len: int = 512) -> str:
    if not isinstance(value, str):
        raise _err(f"{field} must be a string")
    stripped = value.strip()
    if not stripped:
        raise _err(f"{field} must be a non-empty string")
    if len(stripped) > max_len:
        raise _err(f"{field} exceeds {max_len} characters")
    return stripped


def _require_only_keys(payload: Dict[str, Any], allowed: Tuple[str, ...]) -> None:
    extras = set(payload.keys()) - set(allowed)
    if extras:
        raise _err(
            f"unsupported definition keys: {sorted(extras)}; allowed: "
            f"{sorted(allowed)}"
        )


_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]{0,254}$")


def _validate_package_name(name: Any) -> str:
    s = _require_str(name, "package", max_len=255)
    if not _PACKAGE_NAME_RE.match(s):
        raise _err(
            f"package name {s!r} is not a valid Linux package name "
            "(must start with alphanumeric; allowed: letters, digits, "
            "'.', '_', '+', '-')"
        )
    return s


def _validate_package_installed(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise _err("package_installed definition must be an object")
    _require_only_keys(payload, ("package",))
    return {"package": _validate_package_name(payload.get("package"))}


def _validate_package_absent(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise _err("package_absent definition must be an object")
    _require_only_keys(payload, ("package",))
    return {"package": _validate_package_name(payload.get("package"))}


# Accepts the characters Debian and RPM versions are built from, so an
# operator can configure a minimum in the host's own grammar: epochs
# (``1:``), revisions and releases (``-``), and both RPM ordering
# separators (``~`` sorts before the base version, ``^`` after it). A
# version always opens with an alphanumeric, so a separator can never
# lead. Whether the value is well formed for a given family is decided
# by that family's grammar at evaluation time; this only keeps shell
# and control characters out of the stored definition.
_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._:+~^-]{0,127}$")


def _validate_package_version_min(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise _err("package_version_min definition must be an object")
    _require_only_keys(payload, ("package", "min_version"))
    version = payload.get("min_version")
    # fullmatch, not match: ``$`` also matches before a trailing newline,
    # which would let "1.0\n" through into the stored definition.
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version or ""):
        raise _err(
            "min_version must be a non-empty version string "
            "(letters, digits, and . _ : + ~ ^ -)"
        )
    return {
        "package": _validate_package_name(payload.get("package")),
        "min_version": version,
    }


_FACT_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,256}$")


def _validate_fact_key(value: Any) -> str:
    s = _require_str(value, "fact_key", max_len=256)
    if not _FACT_KEY_RE.match(s):
        raise _err(
            "fact_key must be a dotted identifier " "(letters, digits, '.', '_', '-')"
        )
    return s


def _validate_fact_equals(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise _err("fact_equals definition must be an object")
    _require_only_keys(payload, ("fact_key", "expected"))
    expected = payload.get("expected")
    # ``bool`` is a subclass of ``int``; check it first so True/False
    # never masquerade as 1/0 in later evidence comparisons.
    if isinstance(expected, bool):
        raise _err("expected booleans are not accepted to avoid 1/0 coercion")
    if not isinstance(expected, (str, int, float)):
        raise _err("expected must be a string, integer, or float")
    return {
        "fact_key": _validate_fact_key(payload.get("fact_key")),
        "expected": expected,
    }


def _validate_fact_present(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise _err("fact_present definition must be an object")
    _require_only_keys(payload, ("fact_key",))
    return {"fact_key": _validate_fact_key(payload.get("fact_key"))}


def _validate_fact_absent(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise _err("fact_absent definition must be an object")
    _require_only_keys(payload, ("fact_key",))
    return {"fact_key": _validate_fact_key(payload.get("fact_key"))}


def _validate_absolute_path(value: Any) -> str:
    s = _require_str(value, "path", max_len=1024)
    if not s.startswith("/"):
        raise _err("path must be absolute (start with '/')")
    if "\x00" in s or any(ord(c) < 0x20 for c in s):
        raise _err("path must not contain NUL or control characters")
    return s


def _validate_file_exists(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise _err("file_exists definition must be an object")
    _require_only_keys(payload, ("path",))
    return {"path": _validate_absolute_path(payload.get("path"))}


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _validate_file_sha256(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise _err("file_sha256 definition must be an object")
    _require_only_keys(payload, ("path", "sha256"))
    digest = payload.get("sha256")
    if not isinstance(digest, str) or not _SHA256_RE.match(digest):
        raise _err("sha256 must be a 64-character lowercase hex digest")
    return {
        "path": _validate_absolute_path(payload.get("path")),
        "sha256": digest,
    }


def _validate_command_string(value: Any) -> str:
    # Slice 1 does NOT execute commands — we only validate the stored
    # shape so the future PRA-166 runner has a stable surface to consume.
    s = _require_str(value, "command", max_len=2048)
    if "\x00" in s:
        raise _err("command must not contain NUL bytes")
    return s


def _validate_command_stdout_contains(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise _err("command_stdout_contains definition must be an object")
    _require_only_keys(payload, ("command", "expected_substring"))
    substring = payload.get("expected_substring")
    if not isinstance(substring, str) or not substring:
        raise _err("expected_substring must be a non-empty string")
    if len(substring) > 1024:
        raise _err("expected_substring exceeds 1024 characters")
    return {
        "command": _validate_command_string(payload.get("command")),
        "expected_substring": substring,
    }


def _validate_command_exit_code(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise _err("command_exit_code definition must be an object")
    _require_only_keys(payload, ("command", "expected_exit_code"))
    code = payload.get("expected_exit_code")
    if isinstance(code, bool) or not isinstance(code, int):
        raise _err(
            "expected_exit_code must be an integer 0..255 "
            "(booleans are not accepted to avoid 1/0 coercion)"
        )
    if not (0 <= code <= 255):
        raise _err("expected_exit_code must be in range 0..255")
    return {
        "command": _validate_command_string(payload.get("command")),
        "expected_exit_code": code,
    }


KNOWN_CHECK_KINDS: Dict[str, Dict[str, Any]] = {
    "package_installed": {
        "validator": _validate_package_installed,
        "runner_owner": RUNNER_OWNER_SLICE_2,
    },
    "package_absent": {
        "validator": _validate_package_absent,
        "runner_owner": RUNNER_OWNER_SLICE_2,
    },
    "package_version_min": {
        "validator": _validate_package_version_min,
        "runner_owner": RUNNER_OWNER_SLICE_2,
    },
    "fact_equals": {
        "validator": _validate_fact_equals,
        "runner_owner": RUNNER_OWNER_SLICE_2,
    },
    "fact_present": {
        "validator": _validate_fact_present,
        "runner_owner": RUNNER_OWNER_SLICE_2,
    },
    "fact_absent": {
        "validator": _validate_fact_absent,
        "runner_owner": RUNNER_OWNER_SLICE_2,
    },
    "file_exists": {
        "validator": _validate_file_exists,
        "runner_owner": RUNNER_OWNER_PRA166,
    },
    "file_sha256": {
        "validator": _validate_file_sha256,
        "runner_owner": RUNNER_OWNER_PRA166,
    },
    "command_stdout_contains": {
        "validator": _validate_command_stdout_contains,
        "runner_owner": RUNNER_OWNER_PRA166,
    },
    "command_exit_code": {
        "validator": _validate_command_exit_code,
        "runner_owner": RUNNER_OWNER_PRA166,
    },
}


def runner_owner_for_kind(kind: str) -> str:
    """Return the runner-owner string for a known kind, or raise."""
    if kind not in KNOWN_CHECK_KINDS:
        raise _err(f"unknown check kind: {kind!r}")
    return KNOWN_CHECK_KINDS[kind]["runner_owner"]


def validate_definition(kind: str, definition: Any) -> Dict[str, Any]:
    """Validate ``definition`` against ``kind``, returning a normalized
    dict. Raises :class:`ComplianceError` on unknown kind or bad shape.
    """
    meta = KNOWN_CHECK_KINDS.get(kind)
    if meta is None:
        raise _err(
            f"unknown check kind: {kind!r}; supported: " f"{sorted(KNOWN_CHECK_KINDS)}"
        )
    return meta["validator"](definition)


# ---------------------------------------------------------------------------
# Audit event-type strings — full PRA-165 namespace reserved here per
# the M16 namespace-reservation convention (only emit the ones this
# slice actually fires; later slices will emit the rest).
# ---------------------------------------------------------------------------

AUDIT_COMPLIANCE_POLICY_CREATED = "compliance_policy.created"
AUDIT_COMPLIANCE_POLICY_UPDATED = "compliance_policy.updated"
AUDIT_COMPLIANCE_POLICY_DELETED = "compliance_policy.deleted"
AUDIT_COMPLIANCE_POLICY_ENABLED = "compliance_policy.enabled"
AUDIT_COMPLIANCE_POLICY_DISABLED = "compliance_policy.disabled"

AUDIT_COMPLIANCE_CHECK_CREATED = "compliance_check.created"
AUDIT_COMPLIANCE_CHECK_UPDATED = "compliance_check.updated"
AUDIT_COMPLIANCE_CHECK_DELETED = "compliance_check.deleted"

AUDIT_COMPLIANCE_STARTER_PACK_SEEDED = "compliance_starter_pack.seeded"

# Reserved prefixes for downstream PRA-165/166/167 efforts (no emission yet):
#   compliance_evaluation.*  PRA-165 Slice 2
#   compliance_evidence.*    PRA-165 Slice 2/3
#   compliance_export.*      PRA-165 Slice 3
#   compliance_remediation.* PRA-167


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def _validate_slug(value: Any, field: str) -> str:
    s = _require_str(value, field, max_len=64)
    if not _SLUG_RE.match(s):
        raise _err(
            f"{field} must be 1..64 chars, lowercase alphanumeric "
            "with '_' or '-', starting with a letter or digit"
        )
    return s


def _validate_severity(value: Any, field: str = "severity") -> str:
    s = _require_str(value, field, max_len=16)
    if s not in VALID_SEVERITIES:
        raise _err(f"{field} must be one of: {list(VALID_SEVERITIES)}")
    return s


def _validate_positive_int(value: Any, field: str, max_value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _err(f"{field} must be an integer")
    if not (1 <= value <= max_value):
        raise _err(f"{field} must be in range 1..{max_value}")
    return value


def _require_user(db: Session, user_id: int) -> None:
    if not db.query(User.id).filter(User.id == user_id).first():
        raise _err(f"actor_user_id={user_id} does not reference a user")


def _require_policy(db: Session, policy_id: int) -> CompliancePolicy:
    policy = db.query(CompliancePolicy).filter(CompliancePolicy.id == policy_id).first()
    if policy is None:
        raise _err(f"compliance policy id={policy_id} not found")
    return policy


def _require_check(db: Session, check_id: int) -> CompliancePolicyCheck:
    check = (
        db.query(CompliancePolicyCheck)
        .filter(CompliancePolicyCheck.id == check_id)
        .first()
    )
    if check is None:
        raise _err(f"compliance check id={check_id} not found")
    return check


def _policy_audit_context(policy: CompliancePolicy) -> Dict[str, Any]:
    return {
        "policy_slug": policy.slug,
        "policy_name": policy.name,
        "severity": policy.severity,
        "category": policy.category,
        "enabled": policy.enabled,
        "built_in": policy.built_in,
        "version": policy.version,
        "starter_pack_key": policy.starter_pack_key,
    }


def _check_audit_context(check: CompliancePolicyCheck) -> Dict[str, Any]:
    return {
        "policy_id": check.policy_id,
        "check_slug": check.slug,
        "kind": check.kind,
        "enabled": check.enabled,
        "severity_override": check.severity_override,
    }


# ---------------------------------------------------------------------------
# Read envelopes — slice 1 read surfaces MUST include explicit
# ``runner_status`` / ``runner_owner`` per check so consumers can
# never mistake a stored definition for an evaluated result.
# ---------------------------------------------------------------------------


def check_read_envelope(check: CompliancePolicyCheck) -> Dict[str, Any]:
    """Serialize a check row with explicit runner-status surfacing.

    Timestamps are emitted as absolute-UTC ISO strings ending in ``Z``
    so consumers never mistake the naive-UTC DB shape for local time.
    """
    return {
        "id": check.id,
        "policy_id": check.policy_id,
        "slug": check.slug,
        "title": check.title,
        "description": check.description,
        "kind": check.kind,
        "definition": dict(check.definition_json or {}),
        "severity_override": check.severity_override,
        "remediation_guidance": check.remediation_guidance,
        "enabled": check.enabled,
        "display_order": check.display_order,
        "runner_status": RUNNER_STATUS_NOT_IMPLEMENTED,
        "runner_owner": runner_owner_for_kind(check.kind),
        # PRA-346: product-facing siblings. The raw enums above stay stable; the
        # UI renders these. ``runner_status_label`` corrects the stale legacy
        # ``runner_not_implemented_in_slice_1`` value — the runner is live now.
        "runner_status_label": compliance_labels.runner_status_label(
            RUNNER_STATUS_NOT_IMPLEMENTED
        ),
        "runner_label": compliance_labels.runner_label(
            runner_owner_for_kind(check.kind)
        ),
        "created_at": utc_iso(check.created_at),
        "updated_at": utc_iso(check.updated_at),
    }


def policy_read_envelope(
    policy: CompliancePolicy,
    *,
    db: Optional[Session] = None,
    include_checks: bool = False,
) -> Dict[str, Any]:
    """Serialize a policy. When ``include_checks=True``, ``db`` is
    required so the embedded check list is freshly queried via
    ``list_checks`` instead of the lazy-loaded ORM relationship,
    which can stale-cache under ``expire_on_commit=False`` when the
    same policy ORM instance was touched in an earlier request.
    """
    payload: Dict[str, Any] = {
        "id": policy.id,
        "slug": policy.slug,
        "name": policy.name,
        "description": policy.description,
        "severity": policy.severity,
        "category": policy.category,
        "schedule_interval_hours": policy.schedule_interval_hours,
        "evidence_retention_days": policy.evidence_retention_days,
        "remediation_guidance": policy.remediation_guidance,
        "enabled": policy.enabled,
        "version": policy.version,
        "built_in": policy.built_in,
        "starter_pack_key": policy.starter_pack_key,
        "created_by": policy.created_by,
        "created_at": utc_iso(policy.created_at),
        "updated_at": utc_iso(policy.updated_at),
        # PRA-312 run-status surface.
        "last_run_at": utc_iso(policy.last_run_at) if policy.last_run_at else None,
        "next_run_at": (
            utc_iso(
                policy.last_run_at + timedelta(hours=policy.schedule_interval_hours)
            )
            if policy.last_run_at
            else None
        ),
        "last_run_status": policy.last_run_status,
        "never_run": policy.last_run_at is None,
    }
    if include_checks:
        if db is None:
            raise _err("policy_read_envelope(include_checks=True) requires db")
        payload["checks"] = [check_read_envelope(c) for c in list_checks(db, policy.id)]
    return payload


# ---------------------------------------------------------------------------
# Policy CRUD
# ---------------------------------------------------------------------------


def create_policy(
    db: Session,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    slug: str,
    name: str,
    description: Optional[str] = None,
    severity: str = "medium",
    category: str = "custom",
    schedule_interval_hours: int = 24,
    evidence_retention_days: int = 90,
    remediation_guidance: Optional[str] = None,
    enabled: bool = True,
    built_in: bool = False,
    starter_pack_key: Optional[str] = None,
) -> CompliancePolicy:
    """Create a compliance policy. Validates inputs, persists, then
    emits ``compliance_policy.created`` AFTER its own commit.
    """
    _require_user(db, actor_user_id)
    slug_clean = _validate_slug(slug, "slug")
    name_clean = _require_str(name, "name", max_len=128)
    severity_clean = _validate_severity(severity)
    category_clean = _require_str(category, "category", max_len=64)
    interval_clean = _validate_positive_int(
        schedule_interval_hours, "schedule_interval_hours", max_value=8760
    )
    retention_clean = _validate_positive_int(
        evidence_retention_days, "evidence_retention_days", max_value=3650
    )
    description_clean: Optional[str] = None
    if description is not None:
        if not isinstance(description, str):
            raise _err("description must be a string")
        if len(description) > 4096:
            raise _err("description exceeds 4096 characters")
        description_clean = description
    guidance_clean: Optional[str] = None
    if remediation_guidance is not None:
        if not isinstance(remediation_guidance, str):
            raise _err("remediation_guidance must be a string")
        if len(remediation_guidance) > 16384:
            raise _err("remediation_guidance exceeds 16384 characters")
        guidance_clean = remediation_guidance

    if (
        db.query(CompliancePolicy.id)
        .filter(CompliancePolicy.slug == slug_clean)
        .first()
        is not None
    ):
        raise _err(f"compliance policy slug {slug_clean!r} already exists")

    starter_key_clean: Optional[str] = None
    if starter_pack_key is not None:
        if not isinstance(starter_pack_key, str):
            raise _err("starter_pack_key must be a string")
        starter_key_clean = _require_str(
            starter_pack_key, "starter_pack_key", max_len=128
        )
        if (
            db.query(CompliancePolicy.id)
            .filter(CompliancePolicy.starter_pack_key == starter_key_clean)
            .first()
            is not None
        ):
            raise _err(f"starter_pack_key {starter_key_clean!r} already seeded")

    policy = CompliancePolicy(
        slug=slug_clean,
        name=name_clean,
        description=description_clean,
        severity=severity_clean,
        category=category_clean,
        schedule_interval_hours=interval_clean,
        evidence_retention_days=retention_clean,
        remediation_guidance=guidance_clean,
        enabled=bool(enabled),
        version=1,
        built_in=bool(built_in),
        starter_pack_key=starter_key_clean,
        created_by=actor_user_id,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)

    safe_emit(
        action=AUDIT_COMPLIANCE_POLICY_CREATED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_policy",
        target_id=str(policy.id),
        context=_policy_audit_context(policy),
    )
    return policy


def get_policy(db: Session, policy_id: int) -> Optional[CompliancePolicy]:
    return db.query(CompliancePolicy).filter(CompliancePolicy.id == policy_id).first()


def get_policy_by_slug(db: Session, slug: str) -> Optional[CompliancePolicy]:
    return db.query(CompliancePolicy).filter(CompliancePolicy.slug == slug).first()


def list_policies(
    db: Session,
    *,
    enabled_only: bool = False,
    built_in_only: bool = False,
    offset: int = 0,
    limit: int = 100,
) -> Tuple[List[CompliancePolicy], int]:
    q = db.query(CompliancePolicy)
    if enabled_only:
        q = q.filter(CompliancePolicy.enabled.is_(True))
    if built_in_only:
        q = q.filter(CompliancePolicy.built_in.is_(True))
    total = q.count()
    rows = q.order_by(CompliancePolicy.slug.asc()).offset(offset).limit(limit).all()
    return rows, total


_UPDATABLE_POLICY_FIELDS: Tuple[str, ...] = (
    "name",
    "description",
    "severity",
    "category",
    "schedule_interval_hours",
    "evidence_retention_days",
    "remediation_guidance",
    "enabled",
)


def update_policy(
    db: Session,
    policy_id: int,
    updates: Dict[str, Any],
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> CompliancePolicy:
    """Update a compliance policy. ``slug``/``built_in``/``starter_pack_key``
    are intentionally immutable post-create.

    Toggling ``enabled`` via update emits both ``compliance_policy.updated``
    AND the dedicated ``compliance_policy.enabled``/``.disabled`` event so
    auditors can filter on the state transition without parsing diffs.
    """
    policy = _require_policy(db, policy_id)

    unknown = set(updates.keys()) - set(_UPDATABLE_POLICY_FIELDS)
    if unknown:
        raise _err(
            f"unsupported update fields: {sorted(unknown)}; allowed: "
            f"{list(_UPDATABLE_POLICY_FIELDS)}"
        )
    if not updates:
        raise _err("no fields to update")

    was_enabled = policy.enabled
    will_be_enabled = was_enabled

    for key, value in list(updates.items()):
        if key == "name":
            policy.name = _require_str(value, "name", max_len=128)
        elif key == "description":
            if value is None:
                policy.description = None
            else:
                if not isinstance(value, str):
                    raise _err("description must be a string")
                if len(value) > 4096:
                    raise _err("description exceeds 4096 characters")
                policy.description = value
        elif key == "severity":
            policy.severity = _validate_severity(value)
        elif key == "category":
            policy.category = _require_str(value, "category", max_len=64)
        elif key == "schedule_interval_hours":
            policy.schedule_interval_hours = _validate_positive_int(
                value, "schedule_interval_hours", max_value=8760
            )
        elif key == "evidence_retention_days":
            policy.evidence_retention_days = _validate_positive_int(
                value, "evidence_retention_days", max_value=3650
            )
        elif key == "remediation_guidance":
            if value is None:
                policy.remediation_guidance = None
            else:
                if not isinstance(value, str):
                    raise _err("remediation_guidance must be a string")
                if len(value) > 16384:
                    raise _err("remediation_guidance exceeds 16384 characters")
                policy.remediation_guidance = value
        elif key == "enabled":
            if not isinstance(value, bool):
                raise _err("enabled must be a boolean")
            policy.enabled = value
            will_be_enabled = value

    policy.version = (policy.version or 1) + 1
    db.commit()
    db.refresh(policy)

    safe_emit(
        action=AUDIT_COMPLIANCE_POLICY_UPDATED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_policy",
        target_id=str(policy.id),
        context={
            **_policy_audit_context(policy),
            "updated_fields": sorted(updates.keys()),
        },
    )
    if was_enabled and not will_be_enabled:
        safe_emit(
            action=AUDIT_COMPLIANCE_POLICY_DISABLED,
            outcome="success",
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            target_kind="compliance_policy",
            target_id=str(policy.id),
            context=_policy_audit_context(policy),
        )
    elif will_be_enabled and not was_enabled:
        safe_emit(
            action=AUDIT_COMPLIANCE_POLICY_ENABLED,
            outcome="success",
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            target_kind="compliance_policy",
            target_id=str(policy.id),
            context=_policy_audit_context(policy),
        )
    return policy


def set_policy_enabled(
    db: Session,
    policy_id: int,
    enabled: bool,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> CompliancePolicy:
    """Enable/disable convenience wrapper. Idempotent: if the policy
    is already in the requested state, no write happens and no audit
    event is emitted.
    """
    policy = _require_policy(db, policy_id)
    if policy.enabled == enabled:
        return policy
    policy.enabled = enabled
    policy.version = (policy.version or 1) + 1
    db.commit()
    db.refresh(policy)
    safe_emit(
        action=(
            AUDIT_COMPLIANCE_POLICY_ENABLED
            if enabled
            else AUDIT_COMPLIANCE_POLICY_DISABLED
        ),
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_policy",
        target_id=str(policy.id),
        context=_policy_audit_context(policy),
    )
    return policy


def delete_policy(
    db: Session,
    policy_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> None:
    """Delete a compliance policy. Refuses to drop ``built_in=True``
    rows so the starter pack stays referenceable; operators must
    disable instead.
    """
    policy = _require_policy(db, policy_id)
    if policy.built_in:
        raise _err(
            f"compliance policy {policy.slug!r} is a built-in starter row; "
            "disable it instead of deleting"
        )
    context = _policy_audit_context(policy)
    target_id = str(policy.id)
    db.delete(policy)
    db.commit()
    safe_emit(
        action=AUDIT_COMPLIANCE_POLICY_DELETED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_policy",
        target_id=target_id,
        context=context,
    )


# ---------------------------------------------------------------------------
# Check CRUD
# ---------------------------------------------------------------------------


def add_check(
    db: Session,
    policy_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    slug: str,
    title: str,
    kind: str,
    definition: Dict[str, Any],
    description: Optional[str] = None,
    severity_override: Optional[str] = None,
    remediation_guidance: Optional[str] = None,
    enabled: bool = True,
    display_order: int = 0,
) -> CompliancePolicyCheck:
    """Add a check to ``policy_id``. Validates ``kind`` + ``definition``
    against the typed vocabulary, persists, and emits
    ``compliance_check.created`` AFTER commit.
    """
    policy = _require_policy(db, policy_id)
    slug_clean = _validate_slug(slug, "check slug")
    title_clean = _require_str(title, "title", max_len=256)
    normalized_def = validate_definition(kind, definition)

    description_clean: Optional[str] = None
    if description is not None:
        if not isinstance(description, str):
            raise _err("description must be a string")
        if len(description) > 4096:
            raise _err("description exceeds 4096 characters")
        description_clean = description

    severity_clean: Optional[str] = None
    if severity_override is not None:
        severity_clean = _validate_severity(severity_override, "severity_override")

    guidance_clean: Optional[str] = None
    if remediation_guidance is not None:
        if not isinstance(remediation_guidance, str):
            raise _err("remediation_guidance must be a string")
        if len(remediation_guidance) > 16384:
            raise _err("remediation_guidance exceeds 16384 characters")
        guidance_clean = remediation_guidance

    if isinstance(display_order, bool) or not isinstance(display_order, int):
        raise _err("display_order must be an integer")
    if not (0 <= display_order <= 100_000):
        raise _err("display_order must be in range 0..100000")

    if (
        db.query(CompliancePolicyCheck.id)
        .filter(
            CompliancePolicyCheck.policy_id == policy.id,
            CompliancePolicyCheck.slug == slug_clean,
        )
        .first()
        is not None
    ):
        raise _err(
            f"check slug {slug_clean!r} already exists on policy " f"{policy.slug!r}"
        )

    check = CompliancePolicyCheck(
        policy_id=policy.id,
        slug=slug_clean,
        title=title_clean,
        description=description_clean,
        kind=kind,
        definition_json=normalized_def,
        severity_override=severity_clean,
        remediation_guidance=guidance_clean,
        enabled=bool(enabled),
        display_order=display_order,
    )
    db.add(check)

    # Bump policy version so evidence rows can pin against the new shape.
    policy.version = (policy.version or 1) + 1
    db.commit()
    db.refresh(check)

    safe_emit(
        action=AUDIT_COMPLIANCE_CHECK_CREATED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_check",
        target_id=str(check.id),
        context={
            **_check_audit_context(check),
            "policy_slug": policy.slug,
        },
    )
    return check


_UPDATABLE_CHECK_FIELDS: Tuple[str, ...] = (
    "title",
    "description",
    "definition",
    "severity_override",
    "remediation_guidance",
    "enabled",
    "display_order",
)


def update_check(
    db: Session,
    check_id: int,
    updates: Dict[str, Any],
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> CompliancePolicyCheck:
    """Update a check. ``slug``/``policy_id``/``kind`` are immutable
    post-create: changing ``kind`` would silently invalidate the
    definition schema, and renaming a check would break evidence-row
    cross-references.
    """
    check = _require_check(db, check_id)

    unknown = set(updates.keys()) - set(_UPDATABLE_CHECK_FIELDS)
    if unknown:
        raise _err(
            f"unsupported update fields: {sorted(unknown)}; allowed: "
            f"{list(_UPDATABLE_CHECK_FIELDS)}"
        )
    if not updates:
        raise _err("no fields to update")

    for key, value in updates.items():
        if key == "title":
            check.title = _require_str(value, "title", max_len=256)
        elif key == "description":
            if value is None:
                check.description = None
            else:
                if not isinstance(value, str):
                    raise _err("description must be a string")
                if len(value) > 4096:
                    raise _err("description exceeds 4096 characters")
                check.description = value
        elif key == "definition":
            check.definition_json = validate_definition(check.kind, value)
        elif key == "severity_override":
            if value is None:
                check.severity_override = None
            else:
                check.severity_override = _validate_severity(value, "severity_override")
        elif key == "remediation_guidance":
            if value is None:
                check.remediation_guidance = None
            else:
                if not isinstance(value, str):
                    raise _err("remediation_guidance must be a string")
                if len(value) > 16384:
                    raise _err("remediation_guidance exceeds 16384 characters")
                check.remediation_guidance = value
        elif key == "enabled":
            if not isinstance(value, bool):
                raise _err("enabled must be a boolean")
            check.enabled = value
        elif key == "display_order":
            if isinstance(value, bool) or not isinstance(value, int):
                raise _err("display_order must be an integer")
            if not (0 <= value <= 100_000):
                raise _err("display_order must be in range 0..100000")
            check.display_order = value

    policy = _require_policy(db, check.policy_id)
    policy.version = (policy.version or 1) + 1
    db.commit()
    db.refresh(check)

    safe_emit(
        action=AUDIT_COMPLIANCE_CHECK_UPDATED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_check",
        target_id=str(check.id),
        context={
            **_check_audit_context(check),
            "updated_fields": sorted(updates.keys()),
        },
    )
    return check


def delete_check(
    db: Session,
    check_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> None:
    check = _require_check(db, check_id)
    context = _check_audit_context(check)
    target_id = str(check.id)
    policy_id = check.policy_id
    db.delete(check)
    policy = _require_policy(db, policy_id)
    policy.version = (policy.version or 1) + 1
    db.commit()
    safe_emit(
        action=AUDIT_COMPLIANCE_CHECK_DELETED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_check",
        target_id=target_id,
        context=context,
    )


def list_checks(db: Session, policy_id: int) -> List[CompliancePolicyCheck]:
    """Return all checks for a policy ordered by ``display_order`` then
    by slug. Raises ``ComplianceError`` if the policy does not exist;
    an empty list is the legitimate "no checks" answer.
    """
    _require_policy(db, policy_id)
    return (
        db.query(CompliancePolicyCheck)
        .filter(CompliancePolicyCheck.policy_id == policy_id)
        .order_by(
            CompliancePolicyCheck.display_order.asc(),
            CompliancePolicyCheck.slug.asc(),
        )
        .all()
    )


# ---------------------------------------------------------------------------
# Starter-pack seed
# ---------------------------------------------------------------------------


def starter_pack_preview() -> List[Dict[str, Any]]:
    """Return a read-only preview of the starter pack. Stable shape
    so the UI can render seed-vs-not-seed without seeding.
    """
    # PRA-346: honest coverage signalling. A fact-shaped starter-pack check
    # whose fact_key isn't collected by Praxis yet can never pass (it always
    # evaluates to a "coverage pending" state), so flag those packs instead of
    # letting them look like plain failures. Lazy import avoids the evaluation
    # service <-> this module import cycle.
    from .compliance_evaluation_service import FACT_KEY_TO_HOSTFACTS_COLUMN

    _FACT_KINDS = {"fact_equals", "fact_present", "fact_absent"}

    def _check_coverage_pending(check: Dict[str, Any]) -> bool:
        if check.get("kind") not in _FACT_KINDS:
            return False
        fact_key = (check.get("definition") or {}).get("fact_key")
        return fact_key not in FACT_KEY_TO_HOSTFACTS_COLUMN

    preview: List[Dict[str, Any]] = []
    for entry in STARTER_PACK:
        checks = entry.get("checks", [])
        owners = sorted({runner_owner_for_kind(c["kind"]) for c in checks})
        coverage_pending_count = sum(1 for c in checks if _check_coverage_pending(c))
        preview.append(
            {
                "starter_pack_key": entry["starter_pack_key"],
                "slug": entry["slug"],
                "name": entry["name"],
                "category": entry.get("category", "custom"),
                "severity": entry.get("severity", "medium"),
                "description": entry.get("description"),
                "check_count": len(checks),
                "runner_owners": owners,
                # PRA-346 product-facing siblings.
                "runner_labels": sorted(
                    {compliance_labels.runner_label(o) for o in owners}
                ),
                "coverage_pending_count": coverage_pending_count,
                "has_coverage_pending": coverage_pending_count > 0,
            }
        )
    return preview


def seed_starter_pack(
    db: Session,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Insert any starter-pack policy whose ``starter_pack_key`` is
    not yet present. Idempotent — re-running adds nothing new and
    does not overwrite operator edits to seeded rows.

    Returns ``{"seeded": [...], "skipped": [...]}`` with the
    ``starter_pack_key`` of each entry.

    Emits ``compliance_starter_pack.seeded`` once per actually-inserted
    starter row, after commit. Skipped rows do not emit.
    """
    _require_user(db, actor_user_id)

    existing_keys = {
        row[0]
        for row in db.query(CompliancePolicy.starter_pack_key)
        .filter(CompliancePolicy.starter_pack_key.isnot(None))
        .all()
    }

    seeded_keys: List[str] = []
    skipped_keys: List[str] = []
    newly_inserted: List[CompliancePolicy] = []

    for entry in STARTER_PACK:
        key = entry["starter_pack_key"]
        if key in existing_keys:
            skipped_keys.append(key)
            continue

        # Validate every check up front before adding anything to the
        # session so a malformed entry never produces a partial seed.
        for check_meta in entry.get("checks", []):
            validate_definition(check_meta["kind"], check_meta["definition"])

        policy = CompliancePolicy(
            slug=entry["slug"],
            name=entry["name"],
            description=entry.get("description"),
            severity=entry.get("severity", "medium"),
            category=entry.get("category", "custom"),
            schedule_interval_hours=entry.get("schedule_interval_hours", 24),
            evidence_retention_days=entry.get("evidence_retention_days", 90),
            remediation_guidance=entry.get("remediation_guidance"),
            enabled=True,
            version=1,
            built_in=True,
            starter_pack_key=key,
            created_by=actor_user_id,
        )
        db.add(policy)
        db.flush()  # need policy.id for check FKs

        for check_meta in entry.get("checks", []):
            normalized_def = validate_definition(
                check_meta["kind"], check_meta["definition"]
            )
            check = CompliancePolicyCheck(
                policy_id=policy.id,
                slug=check_meta["slug"],
                title=check_meta["title"],
                description=check_meta.get("description"),
                kind=check_meta["kind"],
                definition_json=normalized_def,
                severity_override=check_meta.get("severity_override"),
                remediation_guidance=check_meta.get("remediation_guidance"),
                enabled=True,
                display_order=check_meta.get("display_order", 0),
            )
            db.add(check)

        seeded_keys.append(key)
        newly_inserted.append(policy)

    db.commit()
    for policy in newly_inserted:
        safe_emit(
            action=AUDIT_COMPLIANCE_STARTER_PACK_SEEDED,
            outcome="success",
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            target_kind="compliance_policy",
            target_id=str(policy.id),
            context={
                **_policy_audit_context(policy),
                "starter_pack_key": policy.starter_pack_key,
            },
        )

    return {
        "seeded": seeded_keys,
        "skipped": skipped_keys,
    }
