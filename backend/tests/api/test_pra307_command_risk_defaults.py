"""PRA-307: launch-quality default command whitelist / validation risk baseline.

PRA-306 fixed the classification plumbing; this proves the DEFAULT seed content
(scripts/populate_command_whitelist.py) plus the most-severe-rule matcher give a
useful baseline: ordinary reads stay low, the account database escalates to medium,
secret/credential reads are denied critical, and privilege escalation is denied
critical instead of unknown — without broadening allowed execution, and idempotently.
"""

from __future__ import annotations

import pytest

from app.db.models import Credential, Group, System
from app.services.command_validation_service import CommandValidationService
from scripts.populate_command_whitelist import (
    create_validation_rules,
    create_whitelist_entries,
)

# --------------------------------------------------------------------- helpers


@pytest.fixture
def system(db, seed_distro):
    g = db.query(Group).filter_by(name="pra307-grp").first()
    if not g:
        g = Group(name="pra307-grp", description="x")
        db.add(g)
        db.flush()
    c = Credential(name="pra307-cred", auth_method="ssh_key", username="root")
    db.add(c)
    db.flush()
    s = System(
        hostname="pra307-host",
        ip_address="10.30.7.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=c.id,
    )
    db.add(s)
    db.flush()
    return s


@pytest.fixture
def seeded(db, admin_user):
    """Seed the default whitelist entries + validation rules into the test DB."""
    create_whitelist_entries(db, admin_user)
    create_validation_rules(db, admin_user)


def _risk(db, system, admin_user, command):
    return CommandValidationService(db).validate_command(
        command, system.id, admin_user.id
    )


# ------------------------------------------------------------- allowed-low


def test_command_risk_whoami_is_low(db, system, admin_user, seeded):
    res = _risk(db, system, admin_user, "whoami")
    assert res["status"] == "allowed"
    assert res["risk_level"] == "low"


def test_command_risk_ls_home_stays_low(db, system, admin_user, seeded):
    res = _risk(db, system, admin_user, "ls /home")
    assert res["status"] == "allowed"
    assert res["risk_level"] == "low"


# ----------------------------------------------------------- sensitive reads


def test_command_risk_cat_passwd_is_at_least_medium(db, system, admin_user, seeded):
    res = _risk(db, system, admin_user, "cat /etc/passwd")
    # Recon-sensitive: escalated to medium (still allowed, with a warning) — not low.
    assert res["risk_level"] == "medium"
    assert res["status"] in ("warning", "allowed")


@pytest.mark.parametrize(
    "command",
    [
        "cat /etc/shadow",
        "cat /home/alice/.ssh/id_rsa",
        "cat /srv/app/.env",
        "cat /root/.kube/config",
        "cat /home/alice/.aws/credentials",
    ],
)
def test_command_risk_secret_reads_denied_critical(
    db, system, admin_user, seeded, command
):
    res = _risk(db, system, admin_user, command)
    assert res["status"] == "denied"
    assert res["risk_level"] == "critical"


def test_command_risk_broad_whitelist_cannot_make_secret_low(
    db, system, admin_user, seeded
):
    # `cat *` is whitelisted low, but the secret-read rule overrides it.
    assert _risk(db, system, admin_user, "cat /etc/hosts")["risk_level"] == "low"
    assert _risk(db, system, admin_user, "cat /etc/shadow")["risk_level"] == "critical"


# --------------------------------------------------------- privileged commands


@pytest.mark.parametrize(
    "command",
    ["sudo whoami", "su -", "doas ls", "pkexec id"],
)
def test_command_risk_privileged_denied_not_unknown(
    db, system, admin_user, seeded, command
):
    res = _risk(db, system, admin_user, command)
    assert res["status"] == "denied"
    # The key regression: privileged-looking commands are classified, never unknown.
    assert res["risk_level"] == "critical"
    assert res["risk_level"] != "unknown"


# --------------------------------------------------------- destructive command


def test_command_risk_destructive_delete_denied_critical(
    db, system, admin_user, seeded
):
    res = _risk(db, system, admin_user, "rm -rf /")
    assert res["status"] == "denied"
    assert res["risk_level"] == "critical"


# ------------------------------------------------------------- idempotency


def test_seed_is_idempotent(db, admin_user):
    from app.db.models import CommandValidationRule, CommandWhitelist

    create_whitelist_entries(db, admin_user)
    create_validation_rules(db, admin_user)
    wl1 = db.query(CommandWhitelist).count()
    rules1 = db.query(CommandValidationRule).count()

    # Re-running must not duplicate Praxis-owned defaults.
    create_whitelist_entries(db, admin_user)
    create_validation_rules(db, admin_user)
    assert db.query(CommandWhitelist).count() == wl1
    assert db.query(CommandValidationRule).count() == rules1


def test_seed_does_not_overwrite_user_customized_rule(db, admin_user):
    """An admin who edits a Praxis default rule keeps their change on re-seed."""
    from app.db.models import CommandValidationRule

    create_validation_rules(db, admin_user)
    rule = (
        db.query(CommandValidationRule)
        .filter(CommandValidationRule.name == "Privilege Escalation Commands")
        .first()
    )
    assert rule is not None
    rule.is_active = False  # admin customization
    db.commit()

    create_validation_rules(db, admin_user)  # re-seed
    db.refresh(rule)
    assert rule.is_active is False  # not clobbered
