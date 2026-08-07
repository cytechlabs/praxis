"""PRA-342: the revocation drain must not open unbounded/hot-repeated SSH.

- Multiple due RevocationWork rows for one host reconcile ONCE per tick (bounded
  SSH), not once per row.
- A host in transport cooldown is skipped with NO SSH; items stay pending.
- An unmanaged-account ownership conflict is classified manual-intervention with a
  deliberately long backoff — NOT hot-retried every 30s.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.access_models import RevocationWork
from app.db.models import Credential, Group, System, SystemMetadata
from app.services import fleet_reconciliation_service as frs
from app.services import revocation_service as rev
from app.services import ssh_service


@pytest.fixture
def group(db):
    g = db.query(Group).filter_by(name="pra342d-grp").first()
    if not g:
        g = Group(name="pra342d-grp", description="x")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def cred(db):
    c = Credential(name="pra342d-cred", auth_method="ssh_key", username="root")
    db.add(c)
    db.flush()
    return c


def _system(db, seed_distro, group, cred, hostname):
    s = System(
        hostname=hostname,
        ip_address="10.34.9.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    md = SystemMetadata(system_id=s.id)
    db.add(md)
    s.system_metadata = md
    db.flush()
    return s


def _work(db, system_id, login):
    w = RevocationWork(
        reason="test",
        system_id=system_id,
        login=login,
        status="pending",
        attempt_count=0,
    )
    db.add(w)
    db.flush()
    return w


def _counts(**over):
    base = {
        "provisioned": 0,
        "removed": 0,
        "errors": 0,
        "skipped": 0,
        "conflicts": 0,
        "manual_intervention": 0,
    }
    base.update(over)
    return base


@pytest.fixture(autouse=True)
def _isolate_drain(monkeypatch):
    # Keep the drain's tail (privilege reconcile) out of these SSH-counting tests,
    # and default the host to not-cooling unless a test overrides it.
    monkeypatch.setattr(frs, "reconcile_pending_privilege", lambda db: None)
    monkeypatch.setattr(ssh_service, "is_host_cooling_down", lambda *a, **k: None)


def test_multiple_work_rows_one_host_reconcile_once(
    db, seed_distro, group, cred, monkeypatch
):
    system = _system(db, seed_distro, group, cred, "pra342d-coalesce")
    calls = {"n": 0}

    def _fake(_db, _sid):
        calls["n"] += 1
        return _counts(errors=1)  # transient failure

    monkeypatch.setattr(frs, "reconcile_system", _fake)

    for lg in ("a", "b", "c"):
        _work(db, system.id, lg)

    rev.drain(db, now=datetime.utcnow())

    # PRA-342: ONE reconcile (≈1 SSH) for 3 due rows on the same host, not 3.
    assert calls["n"] == 1
    rows = db.query(RevocationWork).filter_by(system_id=system.id).all()
    assert len(rows) == 3
    assert all(r.status == "error" for r in rows)
    assert all(r.attempt_count == 1 for r in rows)
    assert all(r.next_retry_at is not None for r in rows)


def test_cooldown_host_is_skipped_with_no_ssh(
    db, seed_distro, group, cred, monkeypatch
):
    system = _system(db, seed_distro, group, cred, "pra342d-cooldown")
    calls = {"n": 0}

    def _fake(_db, _sid):
        calls["n"] += 1
        return _counts()

    monkeypatch.setattr(frs, "reconcile_system", _fake)
    # Host is cooling down (PRA-313): remaining seconds truthy.
    monkeypatch.setattr(ssh_service, "is_host_cooling_down", lambda *a, **k: 42)

    w = _work(db, system.id, "x")
    rev.drain(db, now=datetime.utcnow())
    db.refresh(w)

    assert calls["n"] == 0  # no reconcile => no SSH this tick
    assert w.status == "pending"  # left for a later tick
    assert w.attempt_count == 0  # not consumed


def test_ownership_error_gets_long_backoff_not_hot_retry(
    db, seed_distro, group, cred, monkeypatch
):
    system = _system(db, seed_distro, group, cred, "pra342d-ownership")

    def _fake(_db, _sid):
        # all errors are ownership conflicts -> manual intervention
        return _counts(errors=1, manual_intervention=1)

    monkeypatch.setattr(frs, "reconcile_system", _fake)

    w = _work(db, system.id, "cfreeman")
    now = datetime.utcnow()
    rev.drain(db, now=now)
    db.refresh(w)

    assert w.status == "manual"
    # Deliberately long backoff — NOT the 30s/60s hot-retry curve.
    assert w.next_retry_at is not None
    assert w.next_retry_at >= now + timedelta(hours=1)
    assert "manual intervention" in (w.last_error or "")

    status = rev.revocation_status(db)
    assert status["counts"]["manual"] == 1
    assert system.id in status["pending_systems"]
    assert status["outstanding"][0]["status"] == "manual"


def test_manual_item_is_repicked_after_backoff_and_can_recover(
    db, seed_distro, group, cred, monkeypatch
):
    """A manual-intervention item stays visible and, once its long backoff has
    elapsed (operator fixed the account), the next drain reconciles and completes
    it — proving auto-recovery without a bespoke re-enqueue."""
    system = _system(db, seed_distro, group, cred, "pra342d-recover")

    # First drain: ownership conflict -> manual + long backoff.
    monkeypatch.setattr(
        frs, "reconcile_system", lambda d, s: _counts(errors=1, manual_intervention=1)
    )
    w = _work(db, system.id, "cfreeman")
    rev.drain(db, now=datetime.utcnow())
    db.refresh(w)
    assert w.status == "manual"

    # Simulate the backoff having elapsed + operator remediation (clean reconcile).
    monkeypatch.setattr(frs, "reconcile_system", lambda d, s: _counts())
    later = w.next_retry_at + timedelta(seconds=1)
    rev.drain(db, now=later)
    db.refresh(w)
    assert w.status == "completed"
