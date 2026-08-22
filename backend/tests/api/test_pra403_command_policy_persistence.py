"""PRA-403: command-policy initialization must not restore deleted policy.

Startup runs ``scripts/populate_command_whitelist.py`` on every boot. It used to
treat a missing baseline row as never initialized and recreate it by name, so a
whitelist entry or validation rule an administrator deleted through the API came
back on the next restart, active and carrying the shipped risk and approval
configuration, with no audit event explaining the restoration.

These tests pin the corrected contract: the baseline is applied once and recorded
in ``command_policy_baseline``; deletions are permanent; disabled, edited, and
operator-authored rows are left alone; and re-running initialization is silent.
"""

from __future__ import annotations

import pytest

from app.db.models import (
    CommandDistroMapping,
    CommandPolicyBaseline,
    CommandValidationRule,
    CommandWhitelist,
    SystemAudit,
)
from scripts.populate_command_whitelist import (
    ITEM_TYPE_DISTRO_MAPPING,
    ITEM_TYPE_VALIDATION_RULE,
    ITEM_TYPE_WHITELIST_ENTRY,
    create_distro_mappings,
    create_distros,
    create_validation_rules,
    create_whitelist_entries,
)

# --------------------------------------------------------------------- helpers


def _initialize(db, admin_user):
    """Run the full startup initialization path once."""
    distros = create_distros(db)
    entries = create_whitelist_entries(db, admin_user)
    create_distro_mappings(db, entries, distros)
    create_validation_rules(db, admin_user)


def _entry(db, name):
    return db.query(CommandWhitelist).filter(CommandWhitelist.name == name).first()


def _rule(db, name):
    return (
        db.query(CommandValidationRule)
        .filter(CommandValidationRule.name == name)
        .first()
    )


def _recorded(db, item_type, item_key):
    return (
        db.query(CommandPolicyBaseline)
        .filter(
            CommandPolicyBaseline.item_type == item_type,
            CommandPolicyBaseline.item_key == item_key,
        )
        .count()
    )


def _counts(db):
    return (
        db.query(CommandWhitelist).count(),
        db.query(CommandValidationRule).count(),
        db.query(CommandDistroMapping).count(),
    )


@pytest.fixture
def initialized(db, admin_user):
    """A database that has been through startup initialization once."""
    _initialize(db, admin_user)
    return admin_user


# ------------------------------------------------------------ fresh initialization


def test_fresh_initialization_applies_the_whole_baseline(db, admin_user):
    """A fresh database receives the shipped baseline and records every item."""
    _initialize(db, admin_user)

    entries, rules, mappings = _counts(db)
    assert entries > 0
    assert rules > 0
    assert mappings > 0

    # Every applied item is recorded, and nothing is recorded that was not applied.
    assert (
        db.query(CommandPolicyBaseline)
        .filter(CommandPolicyBaseline.item_type == ITEM_TYPE_WHITELIST_ENTRY)
        .count()
        == entries
    )
    assert (
        db.query(CommandPolicyBaseline)
        .filter(CommandPolicyBaseline.item_type == ITEM_TYPE_VALIDATION_RULE)
        .count()
        == rules
    )
    assert (
        db.query(CommandPolicyBaseline)
        .filter(CommandPolicyBaseline.item_type == ITEM_TYPE_DISTRO_MAPPING)
        .count()
        == mappings
    )

    # Spot-check that the security-relevant defaults are actually present.
    assert _entry(db, "APT Install Package") is not None
    assert _rule(db, "Privilege Escalation Commands") is not None


def test_repeated_initialization_is_a_no_op(db, admin_user):
    """Restarting must not duplicate, reactivate, or overwrite policy."""
    _initialize(db, admin_user)
    before = _counts(db)
    ledger_before = db.query(CommandPolicyBaseline).count()

    _initialize(db, admin_user)
    _initialize(db, admin_user)

    assert _counts(db) == before
    assert db.query(CommandPolicyBaseline).count() == ledger_before


# ------------------------------------------------------------------ deletions hold


def test_deleted_whitelist_entry_stays_deleted(db, authed_client, initialized):
    """The reported defect: a deleted baseline entry must not return on restart."""
    entry = _entry(db, "APT Install Package")
    assert entry is not None

    resp = authed_client.delete(f"/command-whitelist/whitelist/{entry.id}")
    assert resp.status_code == 200
    assert _entry(db, "APT Install Package") is None

    _initialize(db, initialized)

    assert _entry(db, "APT Install Package") is None
    # The record of the original application survives the deletion. That is what
    # keeps initialization from treating the entry as never installed.
    assert _recorded(db, ITEM_TYPE_WHITELIST_ENTRY, "APT Install Package") == 1


def test_deleted_validation_rule_stays_deleted(db, authed_client, initialized):
    rule = _rule(db, "Read Sensitive Secret Files")
    assert rule is not None

    resp = authed_client.delete(f"/command-whitelist/validation-rules/{rule.id}")
    assert resp.status_code == 200
    assert _rule(db, "Read Sensitive Secret Files") is None

    _initialize(db, initialized)

    assert _rule(db, "Read Sensitive Secret Files") is None
    assert _recorded(db, ITEM_TYPE_VALIDATION_RULE, "Read Sensitive Secret Files") == 1


def test_mappings_of_a_deleted_entry_are_not_restored(db, authed_client, initialized):
    """Mappings follow their command: deleting the command retires both."""
    entry = _entry(db, "APT Update")
    assert entry is not None
    assert (
        db.query(CommandDistroMapping)
        .filter(CommandDistroMapping.command_id == entry.id)
        .count()
        > 0
    )

    entry_id = entry.id
    assert (
        authed_client.delete(f"/command-whitelist/whitelist/{entry_id}").status_code
        == 200
    )

    _initialize(db, initialized)

    assert _entry(db, "APT Update") is None
    assert (
        db.query(CommandDistroMapping)
        .filter(CommandDistroMapping.command_id == entry_id)
        .count()
        == 0
    )


def test_mapping_removed_by_an_update_is_not_restored(db, authed_client, initialized):
    """Replacing an entry's mappings with none is a deliberate narrowing."""
    entry = _entry(db, "YUM Install Package")
    assert entry is not None
    entry_id = entry.id

    resp = authed_client.put(
        f"/command-whitelist/whitelist/{entry_id}",
        json={"distro_mappings": []},
    )
    assert resp.status_code == 200

    _initialize(db, initialized)

    assert (
        db.query(CommandDistroMapping)
        .filter(CommandDistroMapping.command_id == entry_id)
        .count()
        == 0
    )


# ------------------------------------------------- customized and operator rows


def test_disabled_and_edited_rows_keep_their_values(db, admin_user, initialized):
    """Disabling or editing a baseline row is a policy decision, not drift."""
    entry = _entry(db, "APT Remove Package")
    entry.is_active = False
    entry.timeout_seconds = 999
    entry.risk_level = "critical"

    rule = _rule(db, "Sudo Usage")
    rule.is_active = False
    rule.severity = "critical"
    db.commit()

    _initialize(db, initialized)

    db.refresh(entry)
    db.refresh(rule)
    assert entry.is_active is False
    assert entry.timeout_seconds == 999
    assert entry.risk_level == "critical"
    assert rule.is_active is False
    assert rule.severity == "critical"


def test_operator_authored_entry_is_untouched(db, admin_user, initialized):
    operator_entry = CommandWhitelist(
        name="Operator Authored Entry",
        description="operator policy",
        command_pattern="echo *",
        is_regex=False,
        risk_level="low",
        category="custom",
        requires_sudo=False,
        timeout_seconds=11,
        created_by=admin_user.id,
    )
    db.add(operator_entry)
    db.commit()

    _initialize(db, initialized)

    db.refresh(operator_entry)
    assert operator_entry.timeout_seconds == 11
    assert (
        db.query(CommandWhitelist)
        .filter(CommandWhitelist.name == "Operator Authored Entry")
        .count()
        == 1
    )
    # An operator row is not a baseline item, so nothing is recorded for it.
    assert _recorded(db, ITEM_TYPE_WHITELIST_ENTRY, "Operator Authored Entry") == 0


# ------------------------------------------------------------- upgrade adoption


def test_untracked_baseline_rows_are_adopted_not_duplicated(db, admin_user):
    """A row installed before tracking existed is adopted, keeping its values.

    This is the state left by an install that ran an earlier release: the policy
    row is present with no record of its application. Initialization must claim
    it rather than add a second row with the same name.
    """
    preexisting = CommandWhitelist(
        name="APT Search",
        description="installed by an earlier release",
        command_pattern="apt-cache search *",
        is_regex=False,
        is_active=False,
        risk_level="high",
        category="package_management",
        requires_sudo=False,
        timeout_seconds=42,
        created_by=admin_user.id,
    )
    db.add(preexisting)
    db.commit()

    _initialize(db, admin_user)

    matches = (
        db.query(CommandWhitelist).filter(CommandWhitelist.name == "APT Search").all()
    )
    assert len(matches) == 1
    assert matches[0].timeout_seconds == 42
    assert matches[0].risk_level == "high"
    assert matches[0].is_active is False
    assert _recorded(db, ITEM_TYPE_WHITELIST_ENTRY, "APT Search") == 1


# --------------------------------------------------------------------- audit truth


def test_initialization_records_no_policy_change_after_a_deletion(
    db, authed_client, initialized
):
    """The deletion audit stays the only account of what happened.

    Initialization runs outside any request context, so it must not restore
    policy: an unaudited restoration would leave the audit trail disagreeing with
    effective policy.
    """
    entry = _entry(db, "APT Show Package Info")
    assert entry is not None
    assert (
        authed_client.delete(f"/command-whitelist/whitelist/{entry.id}").status_code
        == 200
    )

    audits_after_delete = (
        db.query(SystemAudit)
        .filter(SystemAudit.audit_type == "command_whitelist")
        .count()
    )
    delete_audits = (
        db.query(SystemAudit)
        .filter(
            SystemAudit.audit_type == "command_whitelist",
            SystemAudit.operation == "delete",
        )
        .count()
    )
    assert delete_audits == 1

    _initialize(db, initialized)

    assert (
        db.query(SystemAudit)
        .filter(SystemAudit.audit_type == "command_whitelist")
        .count()
        == audits_after_delete
    )
    assert _entry(db, "APT Show Package Info") is None
