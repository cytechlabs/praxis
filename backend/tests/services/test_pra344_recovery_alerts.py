"""PRA-344: host reachability recovery alerts are emitted no matter which backend
path first observes a previously-unreachable host reconnecting.

The recovery emission is centralized in
``notification_service.notify_host_recovered`` and invoked from
``SSHService._update_system_connection_status`` (the single point that sets a host
``connected`` — used by every SSH-backed op AND by the health check's
``test_connection``). ``HealthService`` keeps the ``system_unreachable``
transition; recovery is delegated so it is never doubled.
"""

import pytest

from app.db.models import Credential, Group, Notification, System, SystemMetadata
from app.services.health_service import HealthService
from app.services.ssh_service import SSHService

# --------------------------------------------------------------------- fixtures


@pytest.fixture
def group(db):
    g = db.query(Group).filter_by(name="pra344-grp").first()
    if not g:
        g = Group(name="pra344-grp", description="x")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def cred(db):
    c = db.query(Credential).first()
    if c is None:
        c = Credential(name="pra344-cred", auth_method="ssh_key", username="root")
        db.add(c)
        db.flush()
    return c


def _system(
    db, seed_distro, group, cred, hostname, *, status="Active", conn=None, failures=0
):
    s = System(
        hostname=hostname,
        ip_address="10.132.0.9",
        distro_id=seed_distro.id,
        os_version="22.04",
        status=status,
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    md = SystemMetadata(system_id=s.id)
    md.connection_status = conn
    md.consecutive_failures = failures
    db.add(md)
    s.system_metadata = md
    db.flush()
    return s


def _count(db, type_, hostname):
    # Filter by hostname (unique per test) so counts are isolated from other rows.
    return (
        db.query(Notification)
        .filter(Notification.type == type_, Notification.title.like(f"%{hostname}%"))
        .count()
    )


# ------------------------------------------------- SSHService recovery emission


@pytest.mark.parametrize("offline", ["unreachable", "disconnected", "error"])
def test_ssh_reconnect_emits_recovery_from_offline_states(
    db, seed_distro, group, cred, offline
):
    host = f"pra344-recover-{offline}"
    system = _system(
        db,
        seed_distro,
        group,
        cred,
        host,
        status="Unreachable",
        conn=offline,
        failures=3,
    )
    svc = SSHService(db)

    svc._update_system_connection_status(system, "connected")

    assert _count(db, "system_recovered", host) == 1
    assert system.status == "Active"
    assert system.system_metadata.connection_status == "connected"
    assert system.system_metadata.consecutive_failures == 0


def test_repeated_connected_updates_do_not_spam_recovery(db, seed_distro, group, cred):
    host = "pra344-nospam"
    system = _system(
        db,
        seed_distro,
        group,
        cred,
        host,
        status="Unreachable",
        conn="unreachable",
        failures=3,
    )
    svc = SSHService(db)

    svc._update_system_connection_status(
        system, "connected"
    )  # offline -> connected: one alert
    svc._update_system_connection_status(
        system, "connected"
    )  # already connected: no alert
    svc._update_system_connection_status(system, "connected")

    assert _count(db, "system_recovered", host) == 1


def test_first_ever_connect_is_not_a_recovery(db, seed_distro, group, cred):
    # Fresh host (no prior offline state) connecting for the first time must not
    # emit a spurious recovery.
    host = "pra344-fresh"
    system = _system(
        db, seed_distro, group, cred, host, status="Inactive", conn=None, failures=0
    )
    svc = SSHService(db)

    svc._update_system_connection_status(system, "connected")

    assert _count(db, "system_recovered", host) == 0


def test_auth_failure_does_not_emit_recovery(db, seed_distro, group, cred):
    host = "pra344-auth"
    system = _system(
        db,
        seed_distro,
        group,
        cred,
        host,
        status="Unreachable",
        conn="unreachable",
        failures=5,
    )
    svc = SSHService(db)

    # Reachable-but-not-managed: auth_failed is not a recovery...
    svc._update_system_connection_status(system, "auth_failed")
    assert _count(db, "system_recovered", host) == 0
    assert system.system_metadata.connection_status == "auth_failed"

    # ...and a later successful connect FROM auth_failed is not a recovery either
    # (auth_failed is excluded from the offline set).
    svc._update_system_connection_status(system, "connected")
    assert _count(db, "system_recovered", host) == 0


# --------------------------------------------------------- HealthService paths


def test_health_check_still_emits_unreachable_at_threshold(
    db, seed_distro, group, cred, monkeypatch
):
    host = "pra344-health-unreach"
    # One short of the threshold (2); the failing check tips it over.
    system = _system(
        db,
        seed_distro,
        group,
        cred,
        host,
        status="Active",
        conn="connected",
        failures=1,
    )
    health = HealthService(db)

    monkeypatch.setattr(
        health.ssh_service,
        "test_connection",
        lambda sid, **kw: {
            "system_id": sid,
            "hostname": host,
            "status": "failed",
            "message": "down",
            "response_time_ms": 0,
        },
    )

    health.check_system(system.id)

    assert system.status == "Unreachable"
    assert _count(db, "system_unreachable", host) == 1
    assert _count(db, "system_recovered", host) == 0


def test_health_check_still_emits_recovered_via_shared_helper(
    db, seed_distro, group, cred, monkeypatch
):
    host = "pra344-health-recover"
    system = _system(
        db,
        seed_distro,
        group,
        cred,
        host,
        status="Unreachable",
        conn="unreachable",
        failures=3,
    )
    health = HealthService(db)

    # Simulate a real reconnect: test_connection routes success through the real
    # _update_system_connection_status, which is now the single place that emits
    # recovery — so the health path still alerts, once, via the shared helper.
    def fake_test_connection(sid, **kw):
        s = db.query(System).filter(System.id == sid).first()
        health.ssh_service._update_system_connection_status(s, "connected")
        return {
            "system_id": sid,
            "hostname": host,
            "status": "success",
            "message": "",
            "response_time_ms": 1,
        }

    monkeypatch.setattr(health.ssh_service, "test_connection", fake_test_connection)

    health.check_system(system.id)

    assert _count(db, "system_recovered", host) == 1  # emitted once (not doubled)
    assert _count(db, "system_unreachable", host) == 0
    assert system.status == "Active"
