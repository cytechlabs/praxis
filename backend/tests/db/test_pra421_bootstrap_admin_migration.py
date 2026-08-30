"""PRA-421: the schema and the concurrency behind the first-run record.

The record is what separates an installation that was never initialized from one
whose administrator was deliberately removed, so the guarantees it rests on are
structural: at most one row, and a row that survives the deletion of the account
it describes. Both are database facts here rather than conventions in Python.

"At most one row" takes two constraints, and the tests hold both. Uniqueness on
the marker means nothing on its own, because rows carrying different marker
strings are all distinct and none of them is what the reader looks for; the
check that pins the column to a single literal is what turns uniqueness into a
single row.

The concurrency test drives two real connections. Two backends starting at once
against a fresh database must produce one administrator, not two, and the loser
has to see the winner's committed record rather than its own stale read.
"""

from __future__ import annotations

import os
import threading

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import CheckConstraint, create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.services import bootstrap_admin_service as bootstrap

TABLE = "bootstrap_admin_state"
CHECK_NAME = "ck_bootstrap_admin_state_marker"
PASSWORD = "concurrent-bootstrap-pw"


@pytest.fixture(name="engine")
def engine_fixture(test_engine):
    """The migrated test database. ``test_engine`` applies the chain once."""
    return test_engine


# ------------------------------------------------------------------ shape


def test_the_table_carries_the_base_columns_and_the_record(engine):
    columns = {c["name"]: c for c in inspect(engine).get_columns(TABLE)}

    # The Base convention: every migrated table declares all three.
    assert {"id", "created_at", "updated_at"} <= set(columns)
    assert {"marker", "state", "bootstrap_user_id", "bootstrap_username"} <= set(
        columns
    )
    assert columns["marker"]["nullable"] is False
    assert columns["state"]["nullable"] is False
    assert columns["initialized_at"]["nullable"] is False
    assert columns["bootstrap_user_id"]["nullable"] is True


def test_the_marker_is_unique(engine):
    constraints = inspect(engine).get_unique_constraints(TABLE)
    assert any(c["column_names"] == ["marker"] for c in constraints)


def test_the_record_outlives_the_account_it_describes(engine):
    foreign_keys = inspect(engine).get_foreign_keys(TABLE)
    matches = [
        fk for fk in foreign_keys if fk["constrained_columns"] == ["bootstrap_user_id"]
    ]
    assert (
        len(matches) == 1
    ), f"expected exactly one bootstrap_user_id foreign key, found {len(matches)}"
    reference = matches[0]
    assert reference["referred_table"] == "user"
    # Deleting the administrator must null the reference, never remove the row
    # that says this installation was initialized.
    assert reference["options"]["ondelete"] == "SET NULL"


def test_a_second_row_is_rejected(db):
    """The single-row invariant is enforced by the database, not by convention."""
    from datetime import datetime

    from app.db.models import BootstrapAdminState

    for _ in range(2):
        db.add(
            BootstrapAdminState(
                marker=bootstrap.MARKER,
                state=bootstrap.STATE_PROVISIONED,
                bootstrap_username="praxisadmin",
                initialized_at=datetime.utcnow(),
            )
        )
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_another_marker_value_is_rejected(engine):
    """Uniqueness only counts once the column can hold one value.

    Without this the table would accept any number of rows under different
    marker strings. The reader looks for one literal, so none of them would be
    found, and a first boot would provision over the top of a record that
    already said this installation was initialized. The insert is raw SQL so
    the rejection is demonstrably the database's, not the ORM's.
    """
    with engine.connect() as conn:
        transaction = conn.begin()
        try:
            with pytest.raises(IntegrityError):
                conn.execute(
                    text(
                        f"INSERT INTO {TABLE} "
                        "(marker, state, initialized_at, created_at, updated_at) "
                        "VALUES ('some_other_marker', 'provisioned', "
                        "NOW(), NOW(), NOW())"
                    )
                )
        finally:
            transaction.rollback()


def test_the_check_constraint_reached_the_database(engine):
    with engine.connect() as conn:
        definition = conn.execute(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid = CAST(:table AS regclass) AND conname = :name"
            ),
            {"table": TABLE, "name": CHECK_NAME},
        ).scalar()
    assert definition is not None, f"{CHECK_NAME} is missing from the database"
    assert bootstrap.MARKER in definition


def test_the_model_declares_the_same_check_as_the_migration():
    """Metadata and migration must agree, or a rebuilt schema loses the check.

    Alembic's autogenerate does not compare check constraints, so nothing else
    would notice the model and the migration drifting apart.
    """
    from app.db.models import BootstrapAdminState

    checks = [
        c
        for c in BootstrapAdminState.__table__.constraints
        if isinstance(c, CheckConstraint)
    ]
    assert [c.name for c in checks] == [CHECK_NAME]
    assert str(checks[0].sqltext) == f"marker = '{bootstrap.MARKER}'"


def test_deleting_the_account_keeps_the_record(db, monkeypatch):
    from app.db.models import BootstrapAdminState, User

    monkeypatch.setenv("ADMIN_PASSWORD", PASSWORD)
    monkeypatch.delenv("ADMIN_USERNAME", raising=False)
    bootstrap.ensure_bootstrap_admin(db)

    db.delete(db.query(User).filter(User.username == "praxisadmin").one())
    db.commit()

    record = db.query(BootstrapAdminState).one()
    assert record.bootstrap_user_id is None
    assert record.bootstrap_username == "praxisadmin"


# ------------------------------------------------------------ concurrency


def _advisory_waiters(conn) -> int:
    return conn.execute(
        text(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
            "AND classid = :namespace AND objid = :lock_id AND NOT granted"
        ),
        {
            "namespace": bootstrap.BOOTSTRAP_LOCK_NAMESPACE,
            "lock_id": bootstrap.BOOTSTRAP_LOCK_ID,
        },
    ).scalar()


def _clean(engine, kept_roles):
    """Return the shared test database to exactly the state this test found.

    This is the one test that commits, so it also owns putting back what it
    committed, including any role the initializer created along the way.
    """
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM audit_events WHERE action LIKE 'bootstrap.%'"))
        conn.execute(text(f"DELETE FROM {TABLE}"))
        conn.execute(
            text('DELETE FROM "user" WHERE username = :name'), {"name": "praxisadmin"}
        )
        kept = set(kept_roles)
        present = [row[0] for row in conn.execute(text("SELECT name FROM role")).all()]
        for name in present:
            if name not in kept:
                conn.execute(
                    text("DELETE FROM role WHERE name = :name"), {"name": name}
                )


def test_two_first_boots_produce_one_administrator(engine, monkeypatch):
    """The second boot waits, then reads what the first one committed.

    This is the whole concurrency contract in one test: the advisory lock makes
    the decision exclusive, and READ COMMITTED means the waiter's read after the
    lock sees the winner's record rather than the empty table it started from.
    """
    from datetime import datetime

    from app.db.models import BootstrapAdminState, User

    monkeypatch.setenv("ADMIN_PASSWORD", PASSWORD)
    monkeypatch.delenv("ADMIN_USERNAME", raising=False)

    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with engine.connect() as probe:
        kept_roles = [
            row[0] for row in probe.execute(text("SELECT name FROM role")).all()
        ]
    # Start from the same state this test promises to leave behind, so an
    # interrupted earlier run cannot make a later one report a false failure.
    _clean(engine, kept_roles)
    with engine.connect() as probe:
        assert probe.execute(text(f"SELECT count(*) FROM {TABLE}")).scalar() == 0
        assert probe.execute(text('SELECT count(*) FROM "user"')).scalar() == 0

    winner = Session()
    loser = Session()
    outcome = {}
    observed_wait = False
    try:
        # The winner holds the decision open without having written anything.
        bootstrap._acquire_lock(winner)  # pylint: disable=protected-access

        def run_loser():
            outcome["result"] = bootstrap.ensure_bootstrap_admin(loser)

        thread = threading.Thread(target=run_loser, daemon=True)
        thread.start()

        with engine.connect() as probe:
            for _ in range(200):
                if _advisory_waiters(probe) == 1:
                    observed_wait = True
                    break
                probe.rollback()
                threading.Event().wait(0.05)

        assert observed_wait, "the second boot did not wait for the first"

        winner.add(
            BootstrapAdminState(
                marker=bootstrap.MARKER,
                state=bootstrap.STATE_PROVISIONED,
                bootstrap_username="praxisadmin",
                initialized_at=datetime.utcnow(),
            )
        )
        winner.add(
            User(
                username="praxisadmin",
                email="praxisadmin@praxis.dev",
                hashed_password="not-a-real-hash",
                is_active=True,
            )
        )
        winner.commit()

        thread.join(timeout=30)
        assert not thread.is_alive()
        assert outcome["result"] == bootstrap.ALREADY_INITIALIZED

        with engine.connect() as probe:
            assert probe.execute(text(f"SELECT count(*) FROM {TABLE}")).scalar() == 1
            assert (
                probe.execute(
                    text('SELECT count(*) FROM "user" WHERE username = :name'),
                    {"name": "praxisadmin"},
                ).scalar()
                == 1
            )
    finally:
        winner.rollback()
        winner.close()
        loser.rollback()
        loser.close()
        _clean(engine, kept_roles)


# ------------------------------------------------------------- up/down/up


def test_downgrade_drops_only_this_table_and_re_upgrade_restores_it(engine):
    config = Config("alembic.ini")
    engine.dispose()

    command.downgrade(config, "-1")
    scratch = create_engine(os.environ["DATABASE_URL"])
    try:
        names = set(inspect(scratch).get_table_names())
        assert TABLE not in names
        # Nothing else went with it.
        assert {"user", "role", "audit_events"} <= names
    finally:
        scratch.dispose()

    command.upgrade(config, "head")
    scratch = create_engine(os.environ["DATABASE_URL"])
    try:
        assert TABLE in set(inspect(scratch).get_table_names())
    finally:
        scratch.dispose()
