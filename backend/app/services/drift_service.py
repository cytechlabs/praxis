"""Configuration drift detection (PRA-127).

Evaluates Baseline rules against fleet systems and records BaselineCheck rows
describing compliance or drift.

Rules shape (baselines.rules_json):
    {
      "packages": [
        {"name": "openssh-server", "check": "required"},
        {"name": "telnetd",        "check": "forbidden"},
        {"name": "nginx",          "check": "version_pin", "version": "1.24.0"},
      ],
      "services": [
        {"name": "sshd",          "check": "running"},
        {"name": "cups",          "check": "stopped"},
        {"name": "ufw",           "check": "enabled"},
        {"name": "docker.socket", "check": "disabled"},
      ],
    }
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from sqlalchemy.orm import Session

from ..db.models import Baseline, BaselineCheck, Package, SmartGroupMembership, System

logger = logging.getLogger(__name__)


PACKAGE_CHECKS = {"required", "forbidden", "version_pin"}
SERVICE_CHECKS = {"running", "stopped", "enabled", "disabled"}


class BaselineRuleError(ValueError):
    """Raised when a baseline rules_json body is malformed."""


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_rules(rules: Any) -> None:
    """Validate a rules_json dict. Raises BaselineRuleError on failure."""
    if not isinstance(rules, dict):
        raise BaselineRuleError("rules_json must be an object")
    packages = rules.get("packages", [])
    services = rules.get("services", [])
    if not isinstance(packages, list) or not isinstance(services, list):
        raise BaselineRuleError("packages and services must be arrays")
    if not packages and not services:
        raise BaselineRuleError(
            "baseline must have at least one package or service rule"
        )

    seen_pkg: Set[str] = set()
    for r in packages:
        if not isinstance(r, dict):
            raise BaselineRuleError("package rule must be an object")
        name = r.get("name")
        check = r.get("check")
        if not isinstance(name, str) or not name.strip():
            raise BaselineRuleError("package rule requires a non-empty 'name'")
        if check not in PACKAGE_CHECKS:
            raise BaselineRuleError(
                f"package check must be one of {sorted(PACKAGE_CHECKS)}"
            )
        if check == "version_pin":
            ver = r.get("version")
            if not isinstance(ver, str) or not ver.strip():
                raise BaselineRuleError("version_pin requires a 'version' string")
        dup_key = f"{name}|{check}"
        if dup_key in seen_pkg:
            raise BaselineRuleError(f"duplicate package rule: {name} / {check}")
        seen_pkg.add(dup_key)

    seen_svc: Set[str] = set()
    for r in services:
        if not isinstance(r, dict):
            raise BaselineRuleError("service rule must be an object")
        name = r.get("name")
        check = r.get("check")
        if not isinstance(name, str) or not name.strip():
            raise BaselineRuleError("service rule requires a non-empty 'name'")
        if check not in SERVICE_CHECKS:
            raise BaselineRuleError(
                f"service check must be one of {sorted(SERVICE_CHECKS)}"
            )
        dup_key = f"{name}|{check}"
        if dup_key in seen_svc:
            raise BaselineRuleError(f"duplicate service rule: {name} / {check}")
        seen_svc.add(dup_key)


# ---------------------------------------------------------------------------
# Scope resolution
# ---------------------------------------------------------------------------


def scope_systems(db: Session, baseline: Baseline) -> List[System]:
    """Return active systems targeted by this baseline's scope."""
    q = db.query(System).filter(System.status == "Active")
    if baseline.scope_smart_group_id:
        member_ids = [
            row[0]
            for row in db.query(SmartGroupMembership.system_id).filter(
                SmartGroupMembership.smart_group_id == baseline.scope_smart_group_id
            )
        ]
        if not member_ids:
            return []
        q = q.filter(System.id.in_(member_ids))
    return q.all()


# ---------------------------------------------------------------------------
# PRA-281: baseline target-set fleet-scope visibility.
#
# A baseline fans out to a *set* of target systems (all active systems when
# unscoped, else the active members of its smart group), so — like patch
# executions/jobs — visibility is a subset relationship. ``scope is None`` means
# tenant-wide admin; a scoped caller may see/operate on a baseline only when its
# resolvable ACTIVE target systems are non-empty AND entirely inside their scope.
# This fails closed for:
#   * unscoped (tenant-wide) baselines — they resolve to ALL active systems, so a
#     partially-scoped caller never gets the full set;
#   * mixed-scope smart groups (some members out of scope);
#   * out-of-scope-only smart groups;
#   * empty/unresolvable smart groups (no active members).
# Inactive systems are excluded to match ``scope_systems`` (the same set the
# runner would actually target), so visibility tracks executable reality.
# ---------------------------------------------------------------------------


def baseline_target_system_ids(db: Session, baseline: Baseline) -> Set[int]:
    """The set of ACTIVE system ids a baseline currently targets."""
    return {s.id for s in scope_systems(db, baseline)}


def baseline_visible_to_scope(
    db: Session, baseline: Baseline, scope: Optional[Set[int]]
) -> bool:
    """Whether a baseline is visible/operable in the caller's fleet scope.

    ``scope is None`` (admin) → always. Otherwise:

    * An UNSCOPED baseline (``scope_smart_group_id is None``) is tenant-wide and
      auto-widens as new active systems appear, so it is admin-only — a scoped
      caller can NEVER see or operate on it, even if their grants currently cover
      every active system. This is a structural gate (``scope_smart_group_id is
      None``), NOT a point-in-time subset check.
    * A smart-group-scoped baseline is visible only when its resolvable active
      target systems are non-empty and entirely within scope (fail closed for
      mixed/out-of-scope-only/empty target sets).
    """
    if scope is None:
        return True
    if baseline.scope_smart_group_id is None:
        return False
    ids = baseline_target_system_ids(db, baseline)
    return bool(ids) and ids.issubset(scope)


# ---------------------------------------------------------------------------
# State collection
# ---------------------------------------------------------------------------


def collect_package_state(db: Session, system_id: int) -> Dict[str, str]:
    """Return map of installed package name -> installed version."""
    rows = (
        db.query(Package.name, Package.installed_version)
        .filter(Package.system_id == system_id)
        .all()
    )
    return {name: ver for name, ver in rows}


def collect_service_state(
    ssh_service, system_id: int, names: List[str]
) -> Dict[str, Dict[str, str]]:
    """Query systemctl is-active/is-enabled for each named service.

    Returns map of service name -> {"active": "...", "enabled": "..."}.
    On SSH failure, returns empty dict (caller records error status).
    """
    if not names:
        return {}
    out: Dict[str, Dict[str, str]] = {}
    # Run as one combined shell command to minimise round-trips.
    for name in names:
        safe = "".join(c for c in name if c.isalnum() or c in ".-_@")
        if not safe:
            continue
        cmd = (
            f"echo __ACTIVE__; systemctl is-active {safe} 2>/dev/null || true; "
            f"echo __ENABLED__; systemctl is-enabled {safe} 2>/dev/null || true"
        )
        res = ssh_service.execute_command(system_id, cmd, timeout=10)
        if res.get("exit_code") is None:
            # connection failure — bubble up by returning empty
            raise RuntimeError(
                f"SSH failure probing {safe}: {res.get('stderr') or 'no exit code'}"
            )
        text = res.get("stdout", "")
        # Parse
        active = ""
        enabled = ""
        section = None
        for line in text.splitlines():
            line = line.strip()
            if line == "__ACTIVE__":
                section = "active"
                continue
            if line == "__ENABLED__":
                section = "enabled"
                continue
            if section == "active" and not active:
                active = line
            elif section == "enabled" and not enabled:
                enabled = line
        out[name] = {"active": active, "enabled": enabled}
    return out


# ---------------------------------------------------------------------------
# Diff engine
# ---------------------------------------------------------------------------


def _diff_packages(
    rules: List[Dict[str, Any]], state: Dict[str, str]
) -> List[Dict[str, Any]]:
    """Return list of drift records for package rules."""
    drift: List[Dict[str, Any]] = []
    for r in rules:
        name = r["name"]
        check = r["check"]
        installed = name in state
        if check == "required" and not installed:
            drift.append({"category": "packages", "rule": r, "reason": "not installed"})
        elif check == "forbidden" and installed:
            drift.append(
                {
                    "category": "packages",
                    "rule": r,
                    "reason": f"installed at {state[name]}",
                }
            )
        elif check == "version_pin":
            want = r.get("version")
            if not installed:
                drift.append(
                    {"category": "packages", "rule": r, "reason": "not installed"}
                )
            elif state[name] != want:
                drift.append(
                    {
                        "category": "packages",
                        "rule": r,
                        "reason": f"installed {state[name]} (want {want})",
                    }
                )
    return drift


def _diff_services(
    rules: List[Dict[str, Any]], state: Dict[str, Dict[str, str]]
) -> List[Dict[str, Any]]:
    drift: List[Dict[str, Any]] = []
    for r in rules:
        name = r["name"]
        check = r["check"]
        svc = state.get(name, {"active": "", "enabled": ""})
        active = svc.get("active", "")
        enabled = svc.get("enabled", "")
        if check == "running" and active != "active":
            drift.append(
                {
                    "category": "services",
                    "rule": r,
                    "reason": f"is-active={active or 'unknown'}",
                }
            )
        elif check == "stopped" and active == "active":
            drift.append({"category": "services", "rule": r, "reason": "running"})
        elif check == "enabled" and enabled not in (
            "enabled",
            "enabled-runtime",
            "alias",
        ):
            drift.append(
                {
                    "category": "services",
                    "rule": r,
                    "reason": f"is-enabled={enabled or 'unknown'}",
                }
            )
        elif check == "disabled" and enabled in ("enabled", "enabled-runtime"):
            drift.append(
                {"category": "services", "rule": r, "reason": "is-enabled=enabled"}
            )
    return drift


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def _ssh_factory(db: Session):
    """Lazy import; avoids circular at module load."""
    from .ssh_service import SSHService

    return SSHService(db)


def run_baseline(
    db: Session,
    baseline_id: int,
    ssh_service=None,
) -> Dict[str, int]:
    """Evaluate a baseline across its scope, persist BaselineCheck rows.

    Returns counts: {"compliant": N, "drifted": N, "error": N}.
    """
    baseline = db.query(Baseline).filter(Baseline.id == baseline_id).first()
    if not baseline or not baseline.enabled:
        return {"compliant": 0, "drifted": 0, "error": 0}

    try:
        rules = json.loads(baseline.rules_json)
        validate_rules(rules)
    except (json.JSONDecodeError, BaselineRuleError) as e:
        logger.error("Baseline %d has invalid rules: %s", baseline_id, e)
        return {"compliant": 0, "drifted": 0, "error": 0}

    systems = scope_systems(db, baseline)
    service_names = [r["name"] for r in rules.get("services", [])]
    ssh_service = ssh_service or _ssh_factory(db)

    counts = {"compliant": 0, "drifted": 0, "error": 0}
    now = datetime.utcnow()

    for system in systems:
        try:
            pkg_state = collect_package_state(db, system.id)
            svc_state = collect_service_state(ssh_service, system.id, service_names)
            drift = _diff_packages(
                rules.get("packages", []), pkg_state
            ) + _diff_services(rules.get("services", []), svc_state)
            status = "drifted" if drift else "compliant"
            db.add(
                BaselineCheck(
                    baseline_id=baseline.id,
                    system_id=system.id,
                    run_at=now,
                    status=status,
                    drift_details_json=json.dumps(drift) if drift else None,
                )
            )
            counts[status] += 1
        except Exception as e:  # pylint: disable=broad-except
            logger.warning(
                "Baseline %d error on system %d: %s", baseline.id, system.id, e
            )
            db.add(
                BaselineCheck(
                    baseline_id=baseline.id,
                    system_id=system.id,
                    run_at=now,
                    status="error",
                    drift_details_json=json.dumps({"error": str(e)}),
                )
            )
            counts["error"] += 1

    baseline.last_run_at = now
    db.commit()
    return counts


def run_all_due(db: Session) -> Dict[int, Dict[str, int]]:
    """Run every enabled baseline whose schedule is due. Called by scheduler."""
    now = datetime.utcnow()
    baselines = db.query(Baseline).filter(Baseline.enabled.is_(True)).all()
    stats: Dict[int, Dict[str, int]] = {}
    for b in baselines:
        if b.last_run_at is not None:
            due_at = b.last_run_at + timedelta(hours=b.schedule_interval_hours)
            if now < due_at:
                continue
        try:
            stats[b.id] = run_baseline(db, b.id)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Baseline %d run failed: %s", b.id, e)
    return stats


def purge_old_checks(db: Session, days: int = 90) -> int:
    """Delete BaselineCheck rows older than *days*. Returns rows removed."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    deleted = (
        db.query(BaselineCheck)
        .filter(BaselineCheck.run_at < cutoff)
        .delete(synchronize_session=False)
    )
    db.commit()
    return deleted


# ---------------------------------------------------------------------------
# Read helpers (used by API)
# ---------------------------------------------------------------------------


def latest_check(
    db: Session, baseline_id: int, system_id: int
) -> Optional[BaselineCheck]:
    return (
        db.query(BaselineCheck)
        .filter(
            BaselineCheck.baseline_id == baseline_id,
            BaselineCheck.system_id == system_id,
        )
        .order_by(BaselineCheck.run_at.desc())
        .first()
    )


def drift_summary(
    db: Session, scope_system_ids: Optional[Set[int]] = None
) -> Dict[str, int]:
    """Fleet-wide summary for dashboard widget.

    Counts systems that are currently drifted against any enabled baseline
    (based on latest check per baseline/system pair).

    PRA-281: ``scope_system_ids`` restricts the summary to the caller's fleet
    scope. ``None`` = tenant-wide (admin, unchanged). Otherwise only baselines
    fully visible in scope are counted and only in-scope systems contribute to
    ``drifted_systems`` — an empty scope yields zeroed counts (no accessible
    baseline resolves fully in scope).
    """
    baseline_rows = db.query(Baseline).filter(Baseline.enabled.is_(True)).all()
    if scope_system_ids is not None:
        baseline_rows = [
            b
            for b in baseline_rows
            if baseline_visible_to_scope(db, b, scope_system_ids)
        ]
    baseline_ids = [b.id for b in baseline_rows]
    if not baseline_ids:
        return {"drifted_systems": 0, "baselines": 0}

    # For each (baseline, system), find the latest check.
    from sqlalchemy import func as sa_func

    latest_map = (
        db.query(
            BaselineCheck.baseline_id,
            BaselineCheck.system_id,
            sa_func.max(BaselineCheck.run_at).label("latest"),
        )
        .filter(BaselineCheck.baseline_id.in_(baseline_ids))
        .group_by(BaselineCheck.baseline_id, BaselineCheck.system_id)
        .subquery()
    )
    latest_rows = (
        db.query(BaselineCheck)
        .join(
            latest_map,
            (BaselineCheck.baseline_id == latest_map.c.baseline_id)
            & (BaselineCheck.system_id == latest_map.c.system_id)
            & (BaselineCheck.run_at == latest_map.c.latest),
        )
        .all()
    )
    drifted_systems = {row.system_id for row in latest_rows if row.status == "drifted"}
    if scope_system_ids is not None:
        drifted_systems = {sid for sid in drifted_systems if sid in scope_system_ids}
    return {
        "drifted_systems": len(drifted_systems),
        "baselines": len(baseline_ids),
    }
