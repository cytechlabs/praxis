"""PRA-424: the Default SSH security policy is credited to a real administrator.

The seeder used to look the creator up by the literal username ``admin``. First
run names the bootstrap administrator from ``ADMIN_USERNAME`` and defaults it to
``praxisadmin``, so on a genuinely fresh install that lookup found nothing and
the policy every default resolution depends on was never created.

These tests drive the seeder against installations whose administrator is named
something else, has been renamed, has lost the admin role, or is deactivated.
"""

from __future__ import annotations

import importlib.util
import sys
import uuid
from datetime import datetime
from pathlib import Path

import pytest

from app.core.auth import get_password_hash
from app.db.models import BootstrapAdminState, User
from app.db.ssh_security_models import SSHSecurityPolicy
from app.services import bootstrap_admin_service

_BACKEND_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = _BACKEND_ROOT / "scripts" / "seed_ssh_security_policy.py"


class _KeepOpenSession:
    """Hands the seeder the per-test session while neutering ``close()``."""

    def __init__(self, session):
        self._session = session

    def __getattr__(self, name):
        return getattr(self._session, name)

    @staticmethod
    def close():
        return None


@pytest.fixture
def seeder(db, monkeypatch):
    """The seeder loaded as a module, with its session factory bound to ``db``."""
    spec = importlib.util.spec_from_file_location(
        "seed_ssh_security_policy_owner", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["seed_ssh_security_policy_owner"] = module
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "SessionLocal", lambda: _KeepOpenSession(db))
    yield module
    sys.modules.pop("seed_ssh_security_policy_owner", None)


def _make_user(db, seed_roles, username, *, roles=("admin",), active=True) -> User:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"{username}-{tag}",
        email=f"{username}-{tag}@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=active,
        roles=[seed_roles[name] for name in roles],
    )
    db.add(user)
    db.flush()
    return user


def _record_bootstrap(db, user, *, username=None):
    state = BootstrapAdminState(
        marker=bootstrap_admin_service.MARKER,
        state=bootstrap_admin_service.STATE_PROVISIONED,
        bootstrap_user_id=user.id if user is not None else None,
        bootstrap_username=username or (user.username if user is not None else None),
        initialized_at=datetime.utcnow(),
    )
    db.add(state)
    db.flush()
    return state


def _default(db):
    return db.query(SSHSecurityPolicy).filter_by(name="Default").first()


def test_policy_is_credited_to_the_bootstrap_administrator(db, seed_roles, seeder):
    """The default bootstrap username is not ``admin``, and that must not
    matter: the recorded first-run account is the creator."""
    bootstrap = _make_user(db, seed_roles, "praxisadmin")
    _record_bootstrap(db, bootstrap)

    seeder.main()

    policy = _default(db)
    assert policy is not None
    assert policy.created_by == bootstrap.id
    assert policy.require_host_key_verification is True


def test_policy_is_seeded_without_any_bootstrap_record(db, seed_roles, seeder):
    """An installation that predates the bootstrap record still has an
    administrator, and the oldest active one owns the seeded policy."""
    first = _make_user(db, seed_roles, "operator-one")
    _make_user(db, seed_roles, "operator-two")

    seeder.main()

    policy = _default(db)
    assert policy is not None
    assert policy.created_by == first.id


def test_a_bootstrap_account_stripped_of_admin_is_not_credited(db, seed_roles, seeder):
    """The recorded account stands for the installation only while it is still
    an administrator. A de-roled account is passed over, not resurrected."""
    demoted = _make_user(db, seed_roles, "demoted", roles=("maintainer",))
    _record_bootstrap(db, demoted)
    current = _make_user(db, seed_roles, "current")

    seeder.main()

    policy = _default(db)
    assert policy is not None
    assert policy.created_by == current.id


def test_a_deactivated_bootstrap_account_is_not_credited(db, seed_roles, seeder):
    deactivated = _make_user(db, seed_roles, "deactivated", active=False)
    _record_bootstrap(db, deactivated)
    current = _make_user(db, seed_roles, "current")

    seeder.main()

    policy = _default(db)
    assert policy is not None
    assert policy.created_by == current.id


def test_a_deleted_bootstrap_account_falls_back_to_the_oldest_administrator(
    db, seed_roles, seeder
):
    """``bootstrap_user_id`` nulls out when the account is deleted, so the
    record outlives what it describes and cannot name a creator."""
    _record_bootstrap(db, None, username="praxisadmin")
    current = _make_user(db, seed_roles, "current")

    seeder.main()

    policy = _default(db)
    assert policy is not None
    assert policy.created_by == current.id


def test_no_active_administrator_seeds_nothing(db, seed_roles, seeder):
    """Crediting seeded system data to a non-administrator is refused. The
    policy is created on a later start, once an administrator exists."""
    _make_user(db, seed_roles, "inactive-admin", active=False)
    _make_user(db, seed_roles, "maintainer", roles=("maintainer",))

    seeder.main()

    assert _default(db) is None


def test_rerun_does_not_recredit_an_existing_policy(db, seed_roles, seeder):
    bootstrap = _make_user(db, seed_roles, "praxisadmin")
    _record_bootstrap(db, bootstrap)

    seeder.main()
    first = _default(db)
    assert first is not None
    created_by = first.created_by
    policy_id = first.id

    later = _make_user(db, seed_roles, "later-admin")
    assert later.id != created_by
    seeder.main()

    assert db.query(SSHSecurityPolicy).filter_by(name="Default").count() == 1
    policy = _default(db)
    assert policy.id == policy_id
    assert policy.created_by == created_by
