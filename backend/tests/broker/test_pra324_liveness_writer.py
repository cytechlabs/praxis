"""PRA-324: the production liveness writer persists agent_last_seen_at +
agent_version.

Before PRA-324 the broker never wired a ``last_seen_writer`` in
``main.serve`` (it defaulted to a no-op), so BOTH ``System.agent_last_seen_at``
and ``System.agent_version`` were dead columns — declared, read by the status
API, but never written. These tests pin the extracted DB-mutation helper so
that regression can't return silently.
"""

from __future__ import annotations

from datetime import date

import pytest

from app.broker.main import _AGENT_VERSION_MAX_LEN, _persist_agent_liveness
from app.db.models import Credential, Distro, Group, System


@pytest.fixture
def sys_row(db):
    distro = db.query(Distro).filter_by(name="Ubuntu", version="22.04").first()
    if distro is None:
        distro = Distro(
            name="Ubuntu",
            version="22.04",
            release_date=date(2022, 4, 21),
            end_of_life_date=date(2027, 4, 21),
        )
        db.add(distro)
        db.flush()
    group = db.query(Group).filter_by(name="Default").first()
    if group is None:
        group = Group(name="Default")
        db.add(group)
        db.flush()
    cred = db.query(Credential).filter_by(name="liveness-cred").first()
    if cred is None:
        cred = Credential(
            name="liveness-cred",
            auth_method="password",
            username="root",
            vault_path="v/liveness",
        )
        db.add(cred)
        db.flush()
    s = System(
        hostname="liveness-host",
        ip_address="10.20.0.1",
        distro_id=distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


def test_persist_sets_last_seen_and_version(db, sys_row):
    assert sys_row.agent_last_seen_at is None
    assert sys_row.agent_version is None

    _persist_agent_liveness(db, sys_row.id, "1.2.3")
    db.flush()
    db.refresh(sys_row)

    assert sys_row.agent_last_seen_at is not None
    assert sys_row.agent_version == "1.2.3"


def test_persist_truncates_overlong_version(db, sys_row):
    long_version = "v" * 100
    _persist_agent_liveness(db, sys_row.id, long_version)
    db.flush()
    db.refresh(sys_row)

    assert sys_row.agent_version == long_version[:_AGENT_VERSION_MAX_LEN]
    assert len(sys_row.agent_version) == _AGENT_VERSION_MAX_LEN


def test_persist_none_version_stamps_last_seen_only(db, sys_row):
    sys_row.agent_version = "keep-me"
    db.flush()

    _persist_agent_liveness(db, sys_row.id, None)
    db.flush()
    db.refresh(sys_row)

    # last_seen still advances even when no version is supplied...
    assert sys_row.agent_last_seen_at is not None
    # ...but an empty/None version must not clobber a previously-known one.
    assert sys_row.agent_version == "keep-me"


def test_persist_missing_system_is_noop(db):
    # System deleted between connect and write — must not raise.
    _persist_agent_liveness(db, 999999, "1.0.0")
