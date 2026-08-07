"""PRA-306: command risk classification is carried through validation.

Before this fix the execution path stored ``validation_result.get("risk_level",
"unknown")`` but the whitelist match returned only status/reason/command_id — so a
known command like ``whoami`` displayed ``risk: unknown``. These tests prove the
matched whitelist metadata (risk_level, requires_sudo, category) is now propagated,
that a warning rule escalates risk without downgrading the whitelist baseline, that
denials keep useful classification when available, and that the persisted execution
record / API response carry the resolved values.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.db.command_execution_models import CommandExecutionResult
from app.db.models import (
    CommandDistroMapping,
    CommandValidationRule,
    CommandWhitelist,
    Credential,
    Distro,
    Group,
    System,
)
from app.services.command_execution_service import CommandExecutionService
from app.services.command_validation_service import CommandValidationService

# --------------------------------------------------------------------- helpers


@pytest.fixture
def system(db, seed_distro):
    g = db.query(Group).filter_by(name="pra306-grp").first()
    if not g:
        g = Group(name="pra306-grp", description="x")
        db.add(g)
        db.flush()
    c = Credential(name="pra306-cred", auth_method="ssh_key", username="root")
    db.add(c)
    db.flush()
    s = System(
        hostname="pra306-host",
        ip_address="10.30.6.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=c.id,
    )
    db.add(s)
    db.flush()
    return s


def _whitelist(
    db,
    admin_user,
    *,
    name,
    pattern,
    risk_level,
    requires_sudo=False,
    category="general",
):
    e = CommandWhitelist(
        name=name,
        command_pattern=pattern,
        is_regex=False,
        is_active=True,
        risk_level=risk_level,
        category=category,
        requires_sudo=requires_sudo,
        timeout_seconds=30,
        created_by=admin_user.id,
    )
    db.add(e)
    db.flush()
    return e


def _rule(db, admin_user, *, name, pattern, severity):
    r = CommandValidationRule(
        name=name,
        validation_type="security",
        pattern=pattern,
        is_regex=False,
        is_active=True,
        severity=severity,
        error_message=f"{name} triggered",
        created_by=admin_user.id,
    )
    db.add(r)
    db.flush()
    return r


# --------------------------------------------------- whitelist propagation


def test_whitelisted_low_command_risk_is_low_not_unknown(db, admin_user, system):
    _whitelist(db, admin_user, name="whoami", pattern="whoami", risk_level="low")
    svc = CommandValidationService(db)
    res = svc.validate_command("whoami", system.id, admin_user.id)
    assert res["status"] == "allowed"
    assert res["risk_level"] == "low"  # not "unknown"
    assert res["requires_sudo"] is False


def test_whitelisted_sudo_command_risk_is_high_and_requires_sudo(
    db, admin_user, system
):
    _whitelist(
        db,
        admin_user,
        name="sudo-whoami",
        pattern="sudo whoami",
        risk_level="critical",
        requires_sudo=True,
    )
    svc = CommandValidationService(db)
    res = svc.validate_command("sudo whoami", system.id, admin_user.id)
    assert res["status"] == "allowed"
    assert res["risk_level"] == "critical"
    assert res["requires_sudo"] is True


# --------------------------------------------------- rule escalation (no downgrade)


def test_warning_rule_escalates_low_baseline_upward(db, admin_user, system):
    _whitelist(db, admin_user, name="ls", pattern="ls *", risk_level="low")
    _rule(db, admin_user, name="wildcard-warn", pattern="ls *", severity="warning")
    svc = CommandValidationService(db)
    res = svc.validate_command("ls /etc", system.id, admin_user.id)
    assert res["status"] == "warning"
    # A warning raises risk to at least the warning floor (medium) — above low.
    assert res["risk_level"] == "medium"


def test_warning_rule_never_downgrades_high_baseline(db, admin_user, system):
    _whitelist(
        db,
        admin_user,
        name="risky",
        pattern="risky *",
        risk_level="high",
        requires_sudo=True,
    )
    _rule(db, admin_user, name="risky-warn", pattern="risky *", severity="warning")
    svc = CommandValidationService(db)
    res = svc.validate_command("risky thing", system.id, admin_user.id)
    assert res["status"] == "warning"
    # The whitelist baseline (high) must not be downgraded to the warning floor.
    assert res["risk_level"] == "high"
    assert res["requires_sudo"] is True


# --------------------------------------------------------------- denials


def test_denied_not_in_whitelist_is_unclassified(db, admin_user, system):
    svc = CommandValidationService(db)
    res = svc.validate_command("rm -rf /", system.id, admin_user.id)
    assert res["status"] == "denied"
    # No whitelist match AND no matching rule -> no classification; executor maps
    # this to "unknown".
    assert res["risk_level"] is None


def test_denied_unwhitelisted_command_classified_by_matching_rule(
    db, admin_user, system
):
    """Regression: a dangerous unwhitelisted command is still denied, but a
    matching active critical validation rule now classifies it for audit instead of
    leaving it ``unknown``. Evaluating the rule here is classification-only — the
    command stays denied (execution is not broadened)."""
    _rule(
        db, admin_user, name="destructive-rm", pattern="rm -rf /", severity="critical"
    )
    svc = CommandValidationService(db)
    res = svc.validate_command("rm -rf /", system.id, admin_user.id)
    assert res["status"] == "denied"  # NOT broadened — still denied
    assert res["risk_level"] == "critical"  # classified by the matching rule
    assert res["validation_rule_id"] is not None


def test_denied_for_distro_keeps_matched_entry_risk(
    db, admin_user, system, seed_distro
):
    entry = _whitelist(
        db,
        admin_user,
        name="distro-only",
        pattern="specialcmd",
        risk_level="high",
        requires_sudo=True,
    )
    # A mapping exists but only for a DIFFERENT distro -> unsupported here -> denied,
    # yet the matched entry's classification is preserved for audit.
    from datetime import date

    other = Distro(
        name="OtherOS",
        version="1.0",
        release_date=date(2020, 1, 1),
        end_of_life_date=date(2030, 1, 1),
    )
    db.add(other)
    db.flush()
    db.add(
        CommandDistroMapping(command_id=entry.id, distro_id=other.id, is_supported=True)
    )
    db.flush()
    svc = CommandValidationService(db)
    res = svc.validate_command("specialcmd", system.id, admin_user.id)
    assert res["status"] == "denied"
    assert res["risk_level"] == "high"
    assert res["requires_sudo"] is True


# ------------------------------------- persisted record + API-contract mapping


def test_execution_record_persists_and_returns_classified_risk(db, admin_user, system):
    """The executor maps a classified validation result into the persisted
    CommandExecutionResult and the API-shaped formatted dict (what result/history
    endpoints return) — so a classified command never renders as risk: unknown."""
    svc = CommandExecutionService(db)
    formatted = svc._create_execution_result(
        system_id=system.id,
        user_id=admin_user.id,
        command="sudo whoami",
        command_hash="0" * 64,
        session_id=None,
        ip_address=None,
        user_agent=None,
        execution_context=None,
        started_at=datetime.utcnow(),
        execution_status="failed",
        validation_status="failed",
        error_type="validation_error",
        error_message="denied for distro",
        risk_level="high",
        requires_sudo=True,
        timeout_seconds=30,
    )
    # API-contract: the formatted result the endpoint returns carries the values.
    assert formatted["risk_level"] == "high"
    assert formatted["requires_sudo"] is True
    # And it is persisted immutably on the row.
    row = (
        db.query(CommandExecutionResult)
        .filter(CommandExecutionResult.id == formatted["id"])
        .first()
    )
    assert row is not None
    assert row.risk_level == "high"
    assert row.requires_sudo is True


def test_execution_record_unknown_when_unclassified(db, admin_user, system):
    """A record created without a classification (e.g. bypassed/denied-no-match)
    persists an explicit ``unknown`` risk, not a spurious value."""
    svc = CommandExecutionService(db)
    formatted = svc._create_execution_result(
        system_id=system.id,
        user_id=admin_user.id,
        command="somecmd",
        command_hash="1" * 64,
        session_id=None,
        ip_address=None,
        user_agent=None,
        execution_context=None,
        started_at=datetime.utcnow(),
        execution_status="failed",
        validation_status="failed",
        risk_level="unknown",
        timeout_seconds=30,
    )
    assert formatted["risk_level"] == "unknown"
