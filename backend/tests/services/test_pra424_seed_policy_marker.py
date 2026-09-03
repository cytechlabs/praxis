"""PRA-424: the Default SSH security policy is seeded once per installation.

Absence of a policy named "Default" used to be the whole gate, so a policy an
operator deleted came back on the next restart, and every restart after that.
A durable marker in ``app_settings`` records that this installation has seeded
it, which is what separates "never seeded" from "seeded and then removed".

These drive the seeder's own entry points against the per-test session: first
run, adoption of an installation that predates the marker, the deletion that
must survive any number of reruns, and the concurrent-start races that the two
unique constraints have to settle.
"""

from __future__ import annotations

import importlib.util
import sys
import uuid
from pathlib import Path

import pytest

from app.core.auth import get_password_hash
from app.db.models import AppSettings, Credential, Group, System, User
from app.db.ssh_security_models import SSHSecurityPolicy
from tests.conftest import unique_test_ip

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
        "seed_ssh_security_policy_marker", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["seed_ssh_security_policy_marker"] = module
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "SessionLocal", lambda: _KeepOpenSession(db))
    yield module
    sys.modules.pop("seed_ssh_security_policy_marker", None)


def _make_admin(db, seed_roles) -> User:
    tag = uuid.uuid4().hex[:8]
    admin = User(
        username=f"marker-admin-{tag}",
        email=f"marker-admin-{tag}@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
        roles=[seed_roles["admin"]],
    )
    db.add(admin)
    db.flush()
    return admin


def _make_system(db, seed_distro, *, policy_id=None) -> System:
    tag = uuid.uuid4().hex[:8]
    group = Group(name=f"marker-{tag}")
    credential = Credential(
        name=f"marker-cred-{tag}", auth_method="password", username="root"
    )
    db.add_all([group, credential])
    db.flush()
    system = System(
        hostname=f"marker-{tag}.example.com",
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


def _default(db):
    return db.query(SSHSecurityPolicy).filter_by(name="Default").first()


def _marker(db, seeder):
    return db.query(AppSettings).filter_by(setting_key=seeder.SEED_MARKER_KEY).first()


def test_first_run_creates_the_policy_and_records_the_marker(db, seed_roles, seeder):
    admin = _make_admin(db, seed_roles)
    assert _marker(db, seeder) is None

    seeder.main()

    policy = _default(db)
    assert policy is not None
    assert policy.created_by == admin.id
    marker = _marker(db, seeder)
    assert marker is not None
    assert marker.setting_value == seeder.SEED_MARKER_VALUE


def test_a_deleted_policy_is_not_recreated_by_any_number_of_reruns(
    db, seed_roles, seeder
):
    """The whole point of the marker. Deleting the policy is an operator
    decision, and a restart must not overturn it."""
    _make_admin(db, seed_roles)
    seeder.main()
    policy = _default(db)
    assert policy is not None

    db.delete(policy)
    db.flush()
    assert _default(db) is None

    for _ in range(3):
        seeder.main()

    assert _default(db) is None
    assert _marker(db, seeder) is not None


def test_an_installation_that_predates_the_marker_is_adopted(db, seed_roles, seeder):
    """An existing policy is recorded, never replaced or rewritten."""
    admin = _make_admin(db, seed_roles)
    existing = SSHSecurityPolicy(
        name="Default",
        description="operator-tuned",
        require_host_key_verification=False,
        created_by=admin.id,
    )
    db.add(existing)
    db.flush()
    existing_id = existing.id

    seeder.main()

    policy = _default(db)
    assert policy.id == existing_id
    assert policy.description == "operator-tuned"
    assert policy.require_host_key_verification is False
    assert _marker(db, seeder) is not None
    assert db.query(SSHSecurityPolicy).filter_by(name="Default").count() == 1


def test_adoption_then_deletion_also_stays_deleted(db, seed_roles, seeder):
    """An installation initialized under the old sequence gets exactly one
    corrective chance, and no more after the operator acts."""
    admin = _make_admin(db, seed_roles)
    db.add(SSHSecurityPolicy(name="Default", created_by=admin.id))
    db.flush()

    seeder.main()
    db.delete(_default(db))
    db.flush()
    seeder.main()

    assert _default(db) is None


def test_no_administrator_records_no_marker_so_a_later_start_retries(
    db, seed_roles, seeder
):
    _make_admin(db, seed_roles).is_active = False
    db.flush()

    seeder.main()

    assert _default(db) is None
    assert _marker(db, seeder) is None, "a retry must still be possible"

    _make_admin(db, seed_roles)
    seeder.main()

    assert _default(db) is not None
    assert _marker(db, seeder) is not None


def test_a_concurrent_start_that_wins_the_race_leaves_one_policy_and_one_marker(
    db, seed_roles, seeder, monkeypatch
):
    """The loser trips a unique constraint, rolls back, and reads what the
    winner wrote rather than creating a second policy or a partial state."""
    admin = _make_admin(db, seed_roles)
    original = seeder.resolve_policy_owner
    state = {"raced": False}

    def _racing_resolve(session):
        owner = original(session)
        if not state["raced"]:
            state["raced"] = True
            # The other start commits between our read and our write.
            session.add(
                SSHSecurityPolicy(
                    name="Default",
                    description=seeder.POLICY_DESCRIPTION,
                    created_by=admin.id,
                )
            )
            session.add(
                AppSettings(
                    setting_key=seeder.SEED_MARKER_KEY,
                    setting_value=seeder.SEED_MARKER_VALUE,
                )
            )
            session.commit()
        return owner

    monkeypatch.setattr(seeder, "resolve_policy_owner", _racing_resolve)
    seeder.main()

    assert db.query(SSHSecurityPolicy).filter_by(name="Default").count() == 1
    assert (
        db.query(AppSettings).filter_by(setting_key=seeder.SEED_MARKER_KEY).count() == 1
    )


def test_a_concurrent_adoption_converges_on_one_marker(
    db, seed_roles, seeder, monkeypatch
):
    """Two starts adopting the same pre-existing policy. The one that read
    before the other wrote must converge, not fail the boot."""
    admin = _make_admin(db, seed_roles)
    db.add(SSHSecurityPolicy(name="Default", created_by=admin.id))
    db.commit()
    db.add(
        AppSettings(
            setting_key=seeder.SEED_MARKER_KEY,
            setting_value=seeder.SEED_MARKER_VALUE,
        )
    )
    db.commit()

    # This start read the marker before the other start committed it.
    monkeypatch.setattr(seeder, "read_seed_marker", lambda session: None)
    seeder.main()

    assert (
        db.query(AppSettings).filter_by(setting_key=seeder.SEED_MARKER_KEY).count() == 1
    )
    assert db.query(SSHSecurityPolicy).filter_by(name="Default").count() == 1


def test_the_backfill_runs_when_a_policy_exists(db, seed_distro, seed_roles, seeder):
    _make_admin(db, seed_roles)
    orphan = _make_system(db, seed_distro)

    seeder.main()

    db.refresh(orphan)
    assert orphan.ssh_security_policy_id == _default(db).id


def test_the_backfill_is_skipped_when_the_policy_was_removed(
    db, seed_distro, seed_roles, seeder
):
    """There is nothing to attach a system to, and inventing one would be the
    resurrection the marker exists to prevent."""
    _make_admin(db, seed_roles)
    seeder.main()
    db.delete(_default(db))
    db.flush()
    orphan = _make_system(db, seed_distro)

    seeder.main()

    db.refresh(orphan)
    assert orphan.ssh_security_policy_id is None
    assert _default(db) is None
