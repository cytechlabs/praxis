"""Regression coverage for default-group ID sequence alignment."""

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.db.models import Group
from scripts.seed_data import DISTRO_DEFINITIONS, ROLE_DEFINITIONS, seed_data


def test_default_group_seed_uses_database_generated_id():
    db = MagicMock()
    # One lookup for the group, one per distro, one per role. The group is the
    # only one answered "absent", so it is the only row the run creates, and
    # the list is sized from the seed data so adding a release does not turn
    # this into a StopIteration.
    lookups = len(DISTRO_DEFINITIONS) + len(ROLE_DEFINITIONS)
    db.query.return_value.filter.return_value.first.side_effect = [None] + [
        True
    ] * lookups

    with patch("scripts.seed_data.SessionLocal", return_value=db):
        seed_data()

    # Nothing but the group was added, which is what makes the assertion below
    # about the group rather than about whichever lookup happened to see None.
    assert [type(call.args[0]) for call in db.add.call_args_list] == [Group]

    seeded_groups = [
        call.args[0]
        for call in db.add.call_args_list
        if isinstance(call.args[0], Group)
    ]
    assert len(seeded_groups) == 1
    assert seeded_groups[0].id is None


def test_upgrade_aligns_sequence_to_existing_group_ids():
    migration_path = (
        Path(__file__).parents[2]
        / "alembic/versions/20260810_0001_align_groups_sequence.py"
    )
    spec = importlib.util.spec_from_file_location(
        "align_groups_id_sequence", migration_path
    )
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    with patch.object(migration.op, "execute") as execute:
        migration.upgrade()

    statement = execute.call_args.args[0]
    assert "pg_get_serial_sequence('groups', 'id')" in statement
    assert "COALESCE(MAX(id), 1)" in statement
    assert "MAX(id) IS NOT NULL" in statement
