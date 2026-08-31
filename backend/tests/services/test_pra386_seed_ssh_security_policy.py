"""PRA-386: seed_ssh_security_policy backfill contract.

Drives the seeder's ``main`` against the per-test ``db`` fixture. The backfill
must attach every system that has no SSH security policy to the seeded default,
leave an explicitly assigned system alone, stay idempotent across repeated runs,
and create nothing when there is no administrator to credit the policy to.
"""

from __future__ import annotations

import importlib.util
import sys
import uuid
from pathlib import Path

import pytest

from app.core.auth import get_password_hash
from app.db.models import Credential, Group, System, User
from app.db.ssh_security_models import SSHSecurityPolicy
from tests.conftest import unique_test_ip

_BACKEND_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = _BACKEND_ROOT / "scripts" / "seed_ssh_security_policy.py"


class _KeepOpenSession:
    """Hands the seeder the per-test session while neutering ``close()``.

    ``main`` closes the session it opens, but the fixture owns that lifecycle
    and needs the connection alive to roll the test back afterwards.
    """

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
        "seed_ssh_security_policy", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["seed_ssh_security_policy"] = module
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "SessionLocal", lambda: _KeepOpenSession(db))
    yield module
    sys.modules.pop("seed_ssh_security_policy", None)


def _make_admin(db, seed_roles) -> User:
    admin = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"admin-{uuid.uuid4().hex[:8]}@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
        roles=[seed_roles["admin"]],
    )
    db.add(admin)
    db.flush()
    return admin


def _make_system(db, seed_distro, *, policy_id: int | None = None) -> System:
    tag = uuid.uuid4().hex[:8]
    group = Group(name=f"seed-policy-{tag}")
    credential = Credential(
        name=f"seed-policy-cred-{tag}", auth_method="password", username="root"
    )
    db.add_all([group, credential])
    db.flush()
    system = System(
        hostname=f"seed-policy-{tag}.example.com",
        ip_address=unique_test_ip(),
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=credential.id,
        ssh_security_policy_id=policy_id,
    )
    db.add(system)
    db.flush()
    return system


def test_backfill_attaches_every_orphan_system_to_the_default_policy(
    db, seed_distro, seed_roles, seeder
):
    admin = _make_admin(db, seed_roles)
    explicit = SSHSecurityPolicy(
        name=f"explicit-{uuid.uuid4().hex[:8]}", created_by=admin.id
    )
    db.add(explicit)
    db.flush()

    orphans = [_make_system(db, seed_distro) for _ in range(3)]
    assigned = _make_system(db, seed_distro, policy_id=explicit.id)

    seeder.main()

    default = db.query(SSHSecurityPolicy).filter_by(name="Default").one()
    for system in orphans:
        db.refresh(system)
        assert system.ssh_security_policy_id == default.id

    # An explicit assignment is never overwritten by the backfill.
    db.refresh(assigned)
    assert assigned.ssh_security_policy_id == explicit.id
    assert db.query(System).filter(System.ssh_security_policy_id.is_(None)).count() == 0


def test_rerun_keeps_one_default_policy_and_no_orphans(
    db, seed_distro, seed_roles, seeder
):
    _make_admin(db, seed_roles)
    system = _make_system(db, seed_distro)

    seeder.main()
    default_id = db.query(SSHSecurityPolicy).filter_by(name="Default").one().id
    seeder.main()

    assert db.query(SSHSecurityPolicy).filter_by(name="Default").count() == 1
    db.refresh(system)
    assert system.ssh_security_policy_id == default_id


def test_missing_administrator_seeds_nothing(db, seed_distro, seeder):
    assert db.query(User).count() == 0
    assert db.query(SSHSecurityPolicy).filter_by(name="Default").first() is None
    system = _make_system(db, seed_distro)

    seeder.main()

    assert db.query(SSHSecurityPolicy).filter_by(name="Default").first() is None
    db.refresh(system)
    assert system.ssh_security_policy_id is None
