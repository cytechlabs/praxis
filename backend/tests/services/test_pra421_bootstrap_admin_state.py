"""PRA-421: the bootstrap administrator is provisioned once per installation.

Startup used to create the administrator whenever no user carried the configured
username, so deleting that account meant it came back on the next restart, with
the admin role and the password still in the environment. These tests pin the
durable record that replaces that gate, and they pin it from both sides: an
installation that was never initialized must still get a login, and one that was
must never get a second one.

The table in the approved architecture is reproduced here as tests, one per
pre-record state an upgrade can meet: the configured account present, renamed,
deleted, disabled, stripped of its role, and ADMIN_PASSWORD absent with and
without users.
"""

from __future__ import annotations

import json
from datetime import datetime

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.core.startup_validation import BUNDLED_VAULT_ADDR, StartupValidationError
from app.db.access_models import AuditEvent
from app.db.models import BootstrapAdminState, Role, User
from app.services import bootstrap_admin_service as bootstrap

PASSWORD = "bootstrap-pw-abc123"


def _configure(monkeypatch, *, password=PASSWORD, username=None, email=None):
    """Set the first-run environment. ``None`` unsets the variable."""
    for key, value in (
        ("ADMIN_PASSWORD", password),
        ("ADMIN_USERNAME", username),
        ("ADMIN_EMAIL", email),
    ):
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)


def _production(monkeypatch):
    """A production environment that trips no gate other than the admin one."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("VAULT_ADDR", BUNDLED_VAULT_ADDR)


def _state(db):
    return (
        db.query(BootstrapAdminState)
        .filter(BootstrapAdminState.marker == bootstrap.MARKER)
        .one_or_none()
    )


def _events(db, action):
    return db.query(AuditEvent).filter(AuditEvent.action == action).all()


def _seed_user(db, username, *, roles=(), is_active=True):
    role_rows = []
    for name in roles:
        role = db.query(Role).filter(Role.name == name).first()
        if role is None:
            role = Role(name=name, description=f"{name} role")
            db.add(role)
            db.flush()
        role_rows.append(role)
    user = User(
        username=username,
        email=f"{username}@example.com",
        hashed_password="not-a-real-hash",
        is_active=is_active,
        roles=role_rows,
    )
    db.add(user)
    db.commit()
    return user


# ------------------------------------------------------- fresh installation


def test_fresh_installation_provisions_once_and_records_it(db, monkeypatch):
    _configure(monkeypatch)

    assert bootstrap.ensure_bootstrap_admin(db) == bootstrap.PROVISIONED

    user = db.query(User).filter(User.username == "praxisadmin").one()
    assert user.is_active is True
    assert any(role.name == "admin" for role in user.roles)

    state = _state(db)
    assert state.state == bootstrap.STATE_PROVISIONED
    assert state.bootstrap_user_id == user.id
    assert state.bootstrap_username == "praxisadmin"
    assert state.initialized_at is not None

    events = _events(db, bootstrap.ACTION_PROVISIONED)
    assert len(events) == 1
    event = events[0]
    assert event.outcome == "success"
    assert event.target_kind == "bootstrap_admin"
    # A startup decision has no human actor, so the actor stays empty rather
    # than being given a synthetic identity a log reader could mistake for one.
    assert event.actor_user_id is None
    assert event.actor_username is None
    assert event.actor_ip is None
    assert json.loads(event.context_json) == {
        "username": "praxisadmin",
        "user_id": user.id,
        "state": "provisioned",
    }


def test_second_boot_creates_nothing(db, monkeypatch):
    _configure(monkeypatch)
    bootstrap.ensure_bootstrap_admin(db)

    assert bootstrap.ensure_bootstrap_admin(db) == bootstrap.ALREADY_INITIALIZED

    assert db.query(User).count() == 1
    assert db.query(BootstrapAdminState).count() == 1
    assert len(_events(db, bootstrap.ACTION_PROVISIONED)) == 1


def test_deleted_administrator_is_not_recreated(db, monkeypatch):
    """The defect this change exists to fix."""
    _configure(monkeypatch)
    bootstrap.ensure_bootstrap_admin(db)
    bootstrap_user = db.query(User).filter(User.username == "praxisadmin").one()
    survivor = _seed_user(db, "opslead", roles=("admin",))

    db.delete(bootstrap_user)
    db.commit()

    assert bootstrap.ensure_bootstrap_admin(db) == bootstrap.ALREADY_INITIALIZED

    assert db.query(User).filter(User.username == "praxisadmin").first() is None
    assert db.query(User).count() == 1
    assert db.query(User).one().id == survivor.id

    # The record outlives the account it describes.
    state = _state(db)
    assert state is not None
    assert state.bootstrap_user_id is None
    assert state.bootstrap_username == "praxisadmin"


# ------------------------------------------- adoption of a pre-record install


def test_existing_configured_account_is_adopted_and_bound(db, monkeypatch):
    _configure(monkeypatch)
    existing = _seed_user(db, "praxisadmin", roles=("admin",))

    assert bootstrap.ensure_bootstrap_admin(db) == bootstrap.ADOPTED

    assert db.query(User).count() == 1
    state = _state(db)
    assert state.state == bootstrap.STATE_ADOPTED
    assert state.bootstrap_user_id == existing.id

    context = json.loads(_events(db, bootstrap.ACTION_ADOPTED)[0].context_json)
    assert context["matched_existing"] is True
    assert context["user_id"] == existing.id
    assert context["user_count"] == 1


def test_renamed_administrator_does_not_produce_a_second_account(db, monkeypatch):
    """The old gate keyed on the username, so a rename minted a second admin."""
    _configure(monkeypatch)
    renamed = _seed_user(db, "fleet-owner", roles=("admin",))

    assert bootstrap.ensure_bootstrap_admin(db) == bootstrap.ADOPTED

    assert db.query(User).filter(User.username == "praxisadmin").first() is None
    assert db.query(User).count() == 1
    assert db.query(User).one().id == renamed.id

    state = _state(db)
    assert state.bootstrap_user_id is None
    assert state.bootstrap_username == "praxisadmin"
    context = json.loads(_events(db, bootstrap.ACTION_ADOPTED)[0].context_json)
    assert context["matched_existing"] is False
    assert context["user_id"] is None


def test_disabled_administrator_is_not_reactivated(db, monkeypatch):
    _configure(monkeypatch)
    disabled = _seed_user(db, "praxisadmin", roles=("admin",), is_active=False)

    assert bootstrap.ensure_bootstrap_admin(db) == bootstrap.ADOPTED

    db.refresh(disabled)
    assert disabled.is_active is False
    assert {role.name for role in disabled.roles} == {"admin"}
    assert db.query(User).count() == 1


def test_de_roled_administrator_is_not_re_roled(db, monkeypatch):
    _configure(monkeypatch)
    de_roled = _seed_user(db, "praxisadmin", roles=())

    assert bootstrap.ensure_bootstrap_admin(db) == bootstrap.ADOPTED

    db.refresh(de_roled)
    assert de_roled.roles == []
    assert db.query(User).count() == 1


def test_adoption_leaves_the_password_hash_alone(db, monkeypatch):
    _configure(monkeypatch)
    existing = _seed_user(db, "praxisadmin", roles=("admin",))
    original_hash = existing.hashed_password

    bootstrap.ensure_bootstrap_admin(db)

    db.refresh(existing)
    assert existing.hashed_password == original_hash


def test_existing_users_without_password_are_adopted(db, monkeypatch):
    _configure(monkeypatch, password=None)
    _seed_user(db, "opslead", roles=("admin",))

    assert bootstrap.ensure_bootstrap_admin(db) == bootstrap.ADOPTED
    assert _state(db).state == bootstrap.STATE_ADOPTED
    assert db.query(User).count() == 1


# ------------------------------------------------------ ADMIN_PASSWORD absent


def test_empty_installation_without_password_records_nothing(db, monkeypatch):
    """Nothing was provisioned, so a later boot must still be able to."""
    _configure(monkeypatch, password=None)

    assert bootstrap.ensure_bootstrap_admin(db) == bootstrap.SKIPPED_NO_PASSWORD
    assert db.query(User).count() == 0
    assert _state(db) is None

    _configure(monkeypatch)
    assert bootstrap.ensure_bootstrap_admin(db) == bootstrap.PROVISIONED
    assert db.query(User).filter(User.username == "praxisadmin").count() == 1


def test_production_without_password_on_an_empty_installation_still_fails(
    db, monkeypatch
):
    _production(monkeypatch)
    _configure(monkeypatch, password="")

    with pytest.raises(StartupValidationError, match="ADMIN_PASSWORD is empty"):
        bootstrap.ensure_bootstrap_admin(db)

    assert _state(db) is None
    assert db.query(User).count() == 0


def test_initialized_production_installation_no_longer_needs_the_password(
    db, monkeypatch
):
    """Once initialized, ADMIN_PASSWORD is spent: it is a first-run input.

    An operator who clears it, which is what the documentation now asks for,
    must not be locked out of restarting.
    """
    _configure(monkeypatch)
    bootstrap.ensure_bootstrap_admin(db)

    _production(monkeypatch)
    _configure(monkeypatch, password="")

    assert bootstrap.ensure_bootstrap_admin(db) == bootstrap.ALREADY_INITIALIZED
    assert db.query(User).count() == 1


def test_other_production_gates_still_run_on_an_initialized_installation(
    db, monkeypatch
):
    """Skipping the admin gate must not skip the rest of production validation."""
    _configure(monkeypatch)
    bootstrap.ensure_bootstrap_admin(db)

    monkeypatch.setenv("ENVIRONMENT", "prod")

    with pytest.raises(StartupValidationError, match="ENVIRONMENT='prod'"):
        bootstrap.ensure_bootstrap_admin(db)


# ----------------------------------------------------- the configured username


def test_changing_the_configured_username_creates_no_second_administrator(
    db, monkeypatch
):
    _configure(monkeypatch)
    bootstrap.ensure_bootstrap_admin(db)

    _configure(monkeypatch, username="second-admin")

    assert bootstrap.ensure_bootstrap_admin(db) == bootstrap.ALREADY_INITIALIZED
    assert db.query(User).filter(User.username == "second-admin").first() is None
    assert db.query(User).count() == 1


def test_suppression_is_recorded_only_when_a_recreate_would_have_happened(
    db, monkeypatch
):
    _configure(monkeypatch)
    bootstrap.ensure_bootstrap_admin(db)

    # The configured account is present: the old gate would not have fired.
    bootstrap.ensure_bootstrap_admin(db)
    assert _events(db, bootstrap.ACTION_SUPPRESSED) == []

    db.delete(db.query(User).filter(User.username == "praxisadmin").one())
    db.commit()

    # Deleted, but no password configured: still nothing the old gate would do.
    _configure(monkeypatch, password=None)
    bootstrap.ensure_bootstrap_admin(db)
    assert _events(db, bootstrap.ACTION_SUPPRESSED) == []

    # Deleted with a password still set: exactly the state that used to
    # resurrect the account.
    _configure(monkeypatch)
    bootstrap.ensure_bootstrap_admin(db)

    events = _events(db, bootstrap.ACTION_SUPPRESSED)
    assert len(events) == 1
    assert events[0].actor_user_id is None
    assert events[0].target_kind == "bootstrap_admin"
    assert json.loads(events[0].context_json) == {"username": "praxisadmin"}
    assert db.query(User).count() == 0


# ------------------------------------------------------------------ redaction


def test_no_audit_context_carries_password_material(db, monkeypatch):
    _configure(monkeypatch)
    bootstrap.ensure_bootstrap_admin(db)
    db.delete(db.query(User).filter(User.username == "praxisadmin").one())
    db.commit()
    bootstrap.ensure_bootstrap_admin(db)

    rows = db.query(AuditEvent).filter(AuditEvent.action.like("bootstrap.%")).all()
    assert rows
    for row in rows:
        assert PASSWORD not in (row.context_json or "")
        assert "password" not in (row.context_json or "").lower()


def test_the_record_stores_no_password_material(db, monkeypatch):
    _configure(monkeypatch)
    bootstrap.ensure_bootstrap_admin(db)

    stored = (
        db.execute(
            text("SELECT * FROM bootstrap_admin_state WHERE marker = :marker"),
            {"marker": bootstrap.MARKER},
        )
        .mappings()
        .one()
    )
    for value in stored.values():
        assert PASSWORD not in str(value)


# ---------------------------------------------------------------- concurrency


def test_a_lost_claim_creates_no_account(db, monkeypatch):
    """The unique marker is the backstop behind the advisory lock.

    A caller that reaches the write with the marker already taken must roll back
    everything it staged, the account included, and report the installation as
    initialized rather than leaving a second administrator behind.
    """
    _configure(monkeypatch)
    db.add(
        BootstrapAdminState(
            marker=bootstrap.MARKER,
            state=bootstrap.STATE_PROVISIONED,
            bootstrap_username="praxisadmin",
            initialized_at=datetime.utcnow(),
        )
    )
    db.commit()

    # Force the decision past the read, so the claim itself is what collides.
    monkeypatch.setattr(bootstrap, "read_state", lambda _db: None)

    assert bootstrap.ensure_bootstrap_admin(db) == bootstrap.ALREADY_INITIALIZED
    assert db.query(User).count() == 0
    assert db.query(BootstrapAdminState).count() == 1


def test_an_audit_write_that_will_not_persist_fails_the_boot(db, monkeypatch):
    """Only a lost claim is a race. An unwritable audit event is a fault.

    Both writes can fail with the same exception type and they demand opposite
    responses. Returning the audit failure as the concurrent outcome would
    report "another process did this" while, on this path, the account it was
    creating is being rolled back, and the operator would be left with a
    deployment that has no administrator and no record of why.

    The injected fault is a real one, not a stub: the audit row's actor names a
    user that does not exist, so the database rejects the insert that the audit
    service itself performs.
    """
    _configure(monkeypatch)
    missing_user_id = 10_000_000
    assert db.query(User).filter(User.id == missing_user_id).first() is None

    real_emit = bootstrap.audit_event_service.emit

    def emit_against_a_missing_actor(session, **kwargs):
        kwargs["actor_user_id"] = missing_user_id
        return real_emit(session, **kwargs)

    monkeypatch.setattr(
        bootstrap.audit_event_service, "emit", emit_against_a_missing_actor
    )

    with pytest.raises(IntegrityError):
        bootstrap.ensure_bootstrap_admin(db)

    # Nothing survives the failure: no account, no record, no event.
    assert db.query(User).count() == 0
    assert db.query(BootstrapAdminState).count() == 0
    assert _events(db, bootstrap.ACTION_PROVISIONED) == []
