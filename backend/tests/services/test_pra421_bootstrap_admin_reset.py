"""PRA-421: the operator recovery path for an installation with no login.

Recording that an installation has been initialized deliberately gives up one
thing the old behavior had: an operator who deletes every user no longer gets an
administrator back on the next restart. The reset is the way back, and it is
narrow on purpose. It refuses while any user exists, because the record is what
keeps a deliberately deleted administrator deleted, and an installation that
still has a login does not need it cleared.

It provisions nothing itself. Clearing the record only returns the installation
to its first-boot state; the next start is still the only thing that creates an
account.
"""

from __future__ import annotations

import json

import pytest

from app.db.access_models import AuditEvent
from app.db.models import BootstrapAdminState, Role, User
from app.services import bootstrap_admin_service as bootstrap

PASSWORD = "bootstrap-pw-abc123"


def _configure(monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", PASSWORD)
    monkeypatch.delenv("ADMIN_USERNAME", raising=False)
    monkeypatch.delenv("ADMIN_EMAIL", raising=False)


def _reset_events(db):
    return (
        db.query(AuditEvent).filter(AuditEvent.action == bootstrap.ACTION_RESET).all()
    )


def _delete_all_users(db):
    for user in db.query(User).all():
        db.delete(user)
    db.commit()


def test_reset_is_refused_while_any_user_exists(db, monkeypatch):
    _configure(monkeypatch)
    bootstrap.ensure_bootstrap_admin(db)

    with pytest.raises(bootstrap.BootstrapAdminError, match="1 user"):
        bootstrap.reset_bootstrap_state(db)

    # The record and the account both survive the refusal.
    assert db.query(BootstrapAdminState).count() == 1
    assert db.query(User).count() == 1

    events = _reset_events(db)
    assert len(events) == 1
    assert events[0].outcome == "denied"
    assert events[0].actor_user_id is None
    assert json.loads(events[0].context_json) == {
        "reason": "users_exist",
        "user_count": 1,
    }


def test_reset_is_refused_even_when_the_remaining_user_is_not_an_admin(db, monkeypatch):
    """Any login is a way in, so any login is a reason to refuse."""
    _configure(monkeypatch)
    bootstrap.ensure_bootstrap_admin(db)
    viewer_role = Role(name="viewer", description="viewer role")
    db.add(viewer_role)
    db.flush()
    db.add(
        User(
            username="readonly",
            email="readonly@example.com",
            hashed_password="not-a-real-hash",
            is_active=True,
            roles=[viewer_role],
        )
    )
    db.commit()
    db.delete(db.query(User).filter(User.username == "praxisadmin").one())
    db.commit()

    with pytest.raises(bootstrap.BootstrapAdminError):
        bootstrap.reset_bootstrap_state(db)

    assert db.query(BootstrapAdminState).count() == 1


def test_reset_clears_the_record_when_no_user_remains(db, monkeypatch):
    _configure(monkeypatch)
    bootstrap.ensure_bootstrap_admin(db)
    _delete_all_users(db)

    assert bootstrap.reset_bootstrap_state(db) == bootstrap.RESET_CLEARED

    assert db.query(BootstrapAdminState).count() == 0
    events = [e for e in _reset_events(db) if e.outcome == "success"]
    assert len(events) == 1
    assert events[0].actor_user_id is None
    assert events[0].target_kind == "bootstrap_admin"
    assert json.loads(events[0].context_json) == {
        "previous_state": "provisioned",
        "username": "praxisadmin",
    }


def test_reset_on_an_uninitialized_installation_is_a_no_op(db, monkeypatch):
    assert bootstrap.reset_bootstrap_state(db) == bootstrap.RESET_NOT_INITIALIZED
    assert db.query(BootstrapAdminState).count() == 0
    assert _reset_events(db) == []


def test_the_next_boot_provisions_again_after_a_reset(db, monkeypatch):
    _configure(monkeypatch)
    bootstrap.ensure_bootstrap_admin(db)
    _delete_all_users(db)
    bootstrap.reset_bootstrap_state(db)

    assert bootstrap.ensure_bootstrap_admin(db) == bootstrap.PROVISIONED
    assert db.query(User).filter(User.username == "praxisadmin").count() == 1
    assert db.query(BootstrapAdminState).count() == 1


def test_reset_itself_provisions_nothing(db, monkeypatch):
    _configure(monkeypatch)
    bootstrap.ensure_bootstrap_admin(db)
    _delete_all_users(db)

    bootstrap.reset_bootstrap_state(db)

    assert db.query(User).count() == 0


def test_reset_exposes_no_credential_material(db, monkeypatch, capsys):
    """The script reports what it did, never what the credential is."""
    import scripts.reset_bootstrap_admin as reset_script

    _configure(monkeypatch)
    bootstrap.ensure_bootstrap_admin(db)
    _delete_all_users(db)
    monkeypatch.setattr(reset_script, "SessionLocal", lambda: db)

    assert reset_script.reset_bootstrap_admin() == 0

    printed = capsys.readouterr().out
    assert PASSWORD not in printed
    assert "password" not in printed.lower()
    assert db.query(BootstrapAdminState).count() == 0
    for row in _reset_events(db):
        assert PASSWORD not in (row.context_json or "")


def test_the_script_reports_a_refusal_as_a_failure(db, monkeypatch, capsys):
    import scripts.reset_bootstrap_admin as reset_script

    _configure(monkeypatch)
    bootstrap.ensure_bootstrap_admin(db)
    monkeypatch.setattr(reset_script, "SessionLocal", lambda: db)

    assert reset_script.reset_bootstrap_admin() == 1

    printed = capsys.readouterr().out
    assert "Refused" in printed
    assert PASSWORD not in printed
    assert db.query(BootstrapAdminState).count() == 1
