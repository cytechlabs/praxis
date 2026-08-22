"""PRA-403: the migration that records the already-applied command policy baseline.

The migration creates ``command_policy_baseline`` and, on a database that has
already had the shipped baseline applied, records every baseline item. That
backfill is what stops the first boot after the upgrade from restoring policy the
operator had deleted.

Getting that classification wrong is dangerous in both directions, so these tests
pin it from both sides. Recording the baseline on a database that never received
it would strip the shipped whitelist and validation rules permanently; not
recording it on a database whose rows were all deliberately deleted would put
every one of them back. Only command-policy evidence decides: surviving policy
rows, or an audited deletion naming a shipped item. A user row decides nothing,
because startup creates the admin user immediately before applying the baseline.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

from app.db.models import CommandPolicyBaseline, CommandValidationRule, CommandWhitelist
from scripts.populate_command_whitelist import (
    ITEM_TYPE_DISTRO_MAPPING,
    ITEM_TYPE_VALIDATION_RULE,
    ITEM_TYPE_WHITELIST_ENTRY,
    create_distro_mappings,
    create_distros,
    create_validation_rules,
    create_whitelist_entries,
)

MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "alembic"
    / "versions"
    / "20260821_0001_command_policy_baseline.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location(
        "command_policy_baseline_migration", MIGRATION_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def migration():
    return _load_migration()


# ------------------------------------------------------------------ table shape


def test_migration_created_the_table():
    engine = create_engine(os.environ["DATABASE_URL"])
    columns = {
        c["name"] for c in inspect(engine).get_columns("command_policy_baseline")
    }
    engine.dispose()
    assert {"id", "item_type", "item_key", "created_at", "updated_at"} <= columns


def test_model_matches_the_table():
    assert CommandPolicyBaseline.__tablename__ == "command_policy_baseline"
    assert {"id", "item_type", "item_key", "created_at", "updated_at"} <= set(
        CommandPolicyBaseline.__table__.columns.keys()
    )


def test_an_item_cannot_be_recorded_twice(db):
    """The record is the authority on whether an item was applied; keep it unique."""
    from sqlalchemy.exc import IntegrityError

    db.add(
        CommandPolicyBaseline(item_type=ITEM_TYPE_WHITELIST_ENTRY, item_key="Dup Check")
    )
    db.commit()
    db.add(
        CommandPolicyBaseline(item_type=ITEM_TYPE_WHITELIST_ENTRY, item_key="Dup Check")
    )
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


# ------------------------------------------------- initialized vs not initialized


def _assert_no_command_policy(db):
    for table in ("command_whitelist", "command_validation_rules"):
        count = db.execute(text(f"SELECT count(*) FROM {table}")).scalar()
        assert count == 0, f"{table} must be empty for this check to mean anything"


def test_an_empty_database_has_not_been_initialized(db, migration):
    _assert_no_command_policy(db)
    assert migration._command_policy_was_initialized(db.connection()) is False


def test_an_admin_user_alone_does_not_prove_initialization(db, admin_user, migration):
    """The interrupted first boot: an admin exists but policy was never applied.

    Startup creates the admin user immediately before applying the baseline, so a
    boot interrupted between the two leaves exactly this state. Reading it as an
    existing install would record all 74 items as applied and leave the
    installation without its shipped whitelist and validation rules for good.
    """
    db.flush()
    _assert_no_command_policy(db)
    assert (
        db.execute(text('SELECT count(*) FROM "user"')).scalar() > 0
    ), "an admin user must exist for this check to mean anything"
    assert (
        db.execute(
            text(
                "SELECT count(*) FROM system_audits WHERE operation = 'delete' "
                "AND audit_type IN ('command_whitelist', 'validation_rule')"
            )
        ).scalar()
        == 0
    ), "no command-policy deletion audit may exist for this check to mean anything"

    assert migration._command_policy_was_initialized(db.connection()) is False


def test_surviving_command_policy_proves_initialization(db, admin_user, migration):
    db.add(
        CommandValidationRule(
            name="Pre-existing Rule",
            description="installed by an earlier release",
            validation_type="pattern",
            pattern="anything",
            is_regex=False,
            severity="info",
            error_message="",
            created_by=admin_user.id,
        )
    )
    db.flush()
    assert migration._command_policy_was_initialized(db.connection()) is True


def test_deleting_every_baseline_row_still_proves_initialization(
    db, authed_client, admin_user, migration
):
    """The install that deliberately removed all of it must keep it removed.

    No policy row survives to point at, so the audited deletions are the only
    remaining evidence that the baseline was ever applied. Without them the
    migration would record nothing and the next boot would reinstall every entry
    and rule the operator removed.
    """
    distros = create_distros(db)
    entries = create_whitelist_entries(db, admin_user)
    create_distro_mappings(db, entries, distros)
    create_validation_rules(db, admin_user)

    for entry in db.query(CommandWhitelist).all():
        assert (
            authed_client.delete(f"/command-whitelist/whitelist/{entry.id}").status_code
            == 200
        )
    for rule in db.query(CommandValidationRule).all():
        assert (
            authed_client.delete(
                f"/command-whitelist/validation-rules/{rule.id}"
            ).status_code
            == 200
        )

    _assert_no_command_policy(db)
    assert migration._command_policy_was_initialized(db.connection()) is True


def test_deleting_an_operator_row_does_not_prove_initialization(
    db, authed_client, admin_user, migration
):
    """An operator's own entry is not a baseline item, so removing it proves nothing.

    Without the name check, this audit would look identical to a baseline
    deletion and would suppress the baseline on a database that never had it.
    """
    created = authed_client.post(
        "/command-whitelist/whitelist",
        json={
            "name": "Operator Authored Entry",
            "command_pattern": "echo *",
            "risk_level": "low",
            "category": "custom",
        },
    )
    assert created.status_code == 201
    assert (
        authed_client.delete(
            f"/command-whitelist/whitelist/{created.json()['id']}"
        ).status_code
        == 200
    )

    _assert_no_command_policy(db)
    assert (
        db.execute(
            text(
                "SELECT count(*) FROM system_audits WHERE operation = 'delete' "
                "AND audit_type = 'command_whitelist'"
            )
        ).scalar()
        == 1
    ), "the deletion audit must exist for this check to mean anything"

    assert migration._command_policy_was_initialized(db.connection()) is False


def test_audited_item_name_reads_the_recorded_shapes(migration):
    """Audit values are free-form text, so name recovery must not assume JSON."""
    assert migration._audited_item_name(None) is None
    assert migration._audited_item_name("") is None
    assert (
        migration._audited_item_name('{"name": "APT Update", "pattern": "apt-get"}')
        == "APT Update"
    )
    assert migration._audited_item_name('"APT Update"') == "APT Update"
    assert migration._audited_item_name("APT Update") == "APT Update"
    assert migration._audited_item_name('{"pattern": "apt-get"}') is None


# ------------------------------------------------------------------- key coverage


def test_frozen_keys_name_real_baseline_items(db, admin_user, migration):
    """Every key the migration freezes must match an item initialization applies.

    A key that names nothing would silently suppress a baseline item forever; a
    typo in one would let a deleted item come back once. The lists are a snapshot
    of the baseline at that revision, so they are a subset of what a later
    release ships, never a superset.
    """
    distros = create_distros(db)
    entries = create_whitelist_entries(db, admin_user)
    create_distro_mappings(db, entries, distros)
    create_validation_rules(db, admin_user)

    applied = {
        (row.item_type, row.item_key) for row in db.query(CommandPolicyBaseline).all()
    }
    assert applied, "initialization recorded nothing to compare against"

    frozen = {
        (ITEM_TYPE_WHITELIST_ENTRY, key) for key in migration.SHIPPED_WHITELIST_ENTRIES
    }
    frozen |= {
        (ITEM_TYPE_VALIDATION_RULE, key) for key in migration.SHIPPED_VALIDATION_RULES
    }
    frozen |= {
        (ITEM_TYPE_DISTRO_MAPPING, key) for key in migration.SHIPPED_DISTRO_MAPPINGS
    }

    assert frozen - applied == set()


def test_frozen_keys_use_the_recorded_item_types(migration):
    """The migration writes the same item types initialization reads back."""
    assert migration.SHIPPED_WHITELIST_ENTRIES
    assert migration.SHIPPED_VALIDATION_RULES
    assert migration.SHIPPED_DISTRO_MAPPINGS
    assert len(set(migration.SHIPPED_WHITELIST_ENTRIES)) == len(
        migration.SHIPPED_WHITELIST_ENTRIES
    )
    assert len(set(migration.SHIPPED_VALIDATION_RULES)) == len(
        migration.SHIPPED_VALIDATION_RULES
    )
    assert len(set(migration.SHIPPED_DISTRO_MAPPINGS)) == len(
        migration.SHIPPED_DISTRO_MAPPINGS
    )
