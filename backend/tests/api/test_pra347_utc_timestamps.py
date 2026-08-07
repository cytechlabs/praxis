"""PRA-347: frontend-facing routes must emit unambiguous UTC timestamps.

The DB convention is naive-UTC ``DateTime`` columns. Serialized with a bare
``.isoformat()`` they produce strings like ``2026-08-04T21:24:56`` (no zone
marker); a browser parses those as *local* time, so the timezone-aware frontend
``formatTimestamp`` renders a UTC instant hours off — the reopened activity-feed
bug (a 21:24:56 UTC scan showing as 21:24 EDT instead of 17:24 EDT).

These routes now serialize datetimes through ``app.core.timeutil.utc_iso`` so
every wire timestamp ends in ``Z``. This suite covers the helper and the three
routes fixed in this slice: ``/activity/feed`` (all five sources), ``/audits``,
and ``/fleet/operations`` (list + detail results).
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.timeutil import utc_iso
from app.db.models import (
    Credential,
    FleetOperation,
    FleetOperationResult,
    Group,
    Job,
    JobHistory,
    Notification,
    Package,
    PackageHistory,
    System,
    SystemAudit,
)

# The exact instant from the bug report (naive UTC, as stored in the DB).
REPRO = datetime(2026, 8, 4, 21, 24, 56)
REPRO_Z = "2026-08-04T21:24:56Z"


def _token(client, username: str) -> str:
    res = client.post(
        "/auth/login", data={"username": username, "password": "testpass123"}
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def _hdr(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── utc_iso helper: naive + aware ──────────────────────────────────────────


def test_utc_iso_none_passes_through():
    assert utc_iso(None) is None


def test_utc_iso_naive_is_treated_as_utc_and_suffixed_z():
    assert utc_iso(REPRO) == REPRO_Z


def test_utc_iso_aware_utc_renders_z_not_offset():
    aware = REPRO.replace(tzinfo=timezone.utc)
    assert utc_iso(aware) == REPRO_Z
    assert "+00:00" not in utc_iso(aware)


def test_utc_iso_aware_non_utc_is_converted_to_utc():
    # 17:24:56 at -04:00 (EDT) is the same instant as 21:24:56 UTC.
    eastern = timezone(timedelta(hours=-4))
    aware = datetime(2026, 8, 4, 17, 24, 56, tzinfo=eastern)
    assert utc_iso(aware) == REPRO_Z


# ── seeded activity across every feed source ───────────────────────────────


@pytest.fixture
def feed_rows(db, admin_user, seed_distro):
    """Seed one row per activity-feed source, all stamped at REPRO (UTC)."""
    group = Group(name="pra347-grp")
    db.add(group)
    db.flush()
    cred = Credential(name="pra347-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    system = System(
        hostname="praxis-tserver01",
        ip_address="10.34.7.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(system)
    db.flush()

    # audit
    db.add(
        SystemAudit(
            system_id=system.id,
            audit_type="status",
            changed_by=admin_user.id,
            changed_at=REPRO,
            old_value="Active",
            new_value="Maintenance",
            operation="update",
            created_at=REPRO,
            updated_at=REPRO,
        )
    )
    # fleet_op (+ one per-system result for the detail route)
    op = FleetOperation(
        operation_type="package_scan",
        user_id=admin_user.id,
        target_count=1,
        success_count=1,
        failure_count=0,
        status="completed",
        created_at=REPRO,
        completed_at=REPRO,
    )
    db.add(op)
    db.flush()
    db.add(
        FleetOperationResult(
            fleet_operation_id=op.id,
            system_id=system.id,
            status="success",
            created_at=REPRO,
        )
    )
    # job
    job = Job(
        name="pra347-scan",
        job_type="package_scan",
        status="completed",
        target_type="all",
        created_by=admin_user.id,
    )
    db.add(job)
    db.flush()
    db.add(
        JobHistory(
            job_id=job.id,
            start_time=REPRO,
            status="completed",
            systems_targeted=1,
            systems_completed=1,
            systems_failed=0,
            created_at=REPRO,
        )
    )
    # package
    pkg = Package(
        system_id=system.id,
        name="openssl",
        installed_version="3.0.2",
    )
    db.add(pkg)
    db.flush()
    db.add(
        PackageHistory(
            package_id=pkg.id,
            system_id=system.id,
            operation="update",
            old_version="3.0.1",
            new_version="3.0.2",
            status="completed",
            performed_at=REPRO,
        )
    )
    # notification (the visible "Package scan complete" row; user_id=None = all)
    db.add(
        Notification(
            type="job_completed",
            title="Package scan complete: praxis-tserver01",
            message="scan finished",
            severity="info",
            user_id=None,
            created_at=REPRO,
        )
    )
    db.commit()
    return {"operation_id": op.id, "system_id": system.id}


def test_activity_feed_every_timestamp_is_absolute_utc(client, admin_user, feed_rows):
    res = client.get(
        "/activity/feed", headers=_hdr(_token(client, admin_user.username))
    )
    assert res.status_code == 200, res.text
    items = res.json()["items"]

    # All five sources present (admin has audit-read + tenant-wide package scope).
    sources = {it["source"] for it in items}
    assert sources == {"audit", "fleet_op", "job", "package", "notification"}, sources

    # No feed item may emit a bare (zoneless) timestamp.
    for it in items:
        assert it["timestamp"] is not None
        assert it["timestamp"].endswith("Z"), it
        assert it["timestamp"] == REPRO_Z, it


def test_notification_repro_row_is_unambiguous_utc(client, admin_user, feed_rows):
    res = client.get(
        "/activity/feed?source=notification",
        headers=_hdr(_token(client, admin_user.username)),
    )
    assert res.status_code == 200, res.text
    notif = next(
        it for it in res.json()["items"] if "Package scan complete" in it["description"]
    )
    # The bug: this rendered 4h ahead because the string had no Z.
    assert notif["timestamp"] == REPRO_Z


# ── /audits and /fleet/operations ──────────────────────────────────────────


def test_audits_list_timestamps_end_in_z(client, admin_user, feed_rows):
    res = client.get("/audits", headers=_hdr(_token(client, admin_user.username)))
    assert res.status_code == 200, res.text
    items = res.json()["items"]
    assert items, "seeded audit row should be listed"
    for a in items:
        assert a["changed_at"] == REPRO_Z, a
        assert a["created_at"] is None or a["created_at"].endswith("Z"), a


def test_fleet_operations_list_and_detail_timestamps_end_in_z(
    client, admin_user, feed_rows
):
    token = _token(client, admin_user.username)
    res = client.get("/fleet/operations", headers=_hdr(token))
    assert res.status_code == 200, res.text
    ops = res.json()["items"]
    assert ops, "seeded fleet operation should be listed"
    for o in ops:
        assert o["created_at"] == REPRO_Z, o
        assert o["completed_at"] is None or o["completed_at"].endswith("Z"), o

    detail = client.get(
        f"/fleet/operations/{feed_rows['operation_id']}", headers=_hdr(token)
    )
    assert detail.status_code == 200, detail.text
    results = detail.json()["results"]
    assert results, "seeded per-system result should be present"
    for r in results:
        assert r["created_at"] == REPRO_Z, r
