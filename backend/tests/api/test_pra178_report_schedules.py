"""PRA-178 Slice 5 — scheduled report runs tests.

Covers:

* Service lifecycle (create / update / list / delete) + cadence math
  (``compute_next_run_at``) + idempotency.
* Scheduler tick (``fire_due_schedules``) writes a
  ``triggered_by='system_scheduled'`` ``ReportRun`` row per due
  schedule and advances ``next_run_at`` so a re-fire skips.
* Route GET ``/reports/schedules`` filter + RBAC (admin /
  maintainer / auditor allowed; viewer denied).
* Route POST / PATCH / DELETE write RBAC (admin / maintainer only;
  auditor denied).
* Failure path: a schedule whose dispatcher raises records a
  ``state='failed'`` ``ReportRun`` row and still advances
  ``next_run_at`` so the same bad config does not loop.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.models import ReportRun, ReportSchedule
from app.services import report_run_service, report_schedule_service


def _login(client, user):
    res = client.post(
        "/auth/login",
        data={"username": user.username, "password": "testpass123"},
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Service-level lifecycle
# ---------------------------------------------------------------------------


def test_create_schedule_persists_with_computed_next_run_at(db, admin_user):
    row = report_schedule_service.create_schedule(
        db,
        name="daily patch executions",
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        cadence="daily",
        filters_snapshot={"state": "succeeded"},
        format="csv",
        created_by_user_id=admin_user.id,
    )
    assert row.id is not None
    assert row.enabled is True
    assert row.cadence == "daily"
    assert row.report_kind == "patch_executions"
    assert row.format == "csv"
    assert row.next_run_at is not None
    # Default first_run_at is now + 1 day (daily cadence).
    expected = datetime.utcnow() + timedelta(days=1)
    assert abs((row.next_run_at - expected).total_seconds()) < 60


def test_create_schedule_rejects_bad_cadence(db, admin_user):
    with pytest.raises(report_schedule_service.ReportScheduleError):
        report_schedule_service.create_schedule(
            db,
            name="bad",
            report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
            cadence="hourly",
            created_by_user_id=admin_user.id,
        )


def test_create_schedule_rejects_bad_kind(db, admin_user):
    with pytest.raises(report_schedule_service.ReportScheduleError):
        report_schedule_service.create_schedule(
            db,
            name="bad",
            report_kind="not_a_kind",
            cadence="daily",
            created_by_user_id=admin_user.id,
        )


def test_compute_next_run_at_daily_weekly_monthly():
    anchor = datetime(2026, 1, 1, 0, 0, 0)
    assert report_schedule_service.compute_next_run_at(
        "daily", anchor
    ) == anchor + timedelta(days=1)
    assert report_schedule_service.compute_next_run_at(
        "weekly", anchor
    ) == anchor + timedelta(days=7)
    assert report_schedule_service.compute_next_run_at(
        "monthly", anchor
    ) == anchor + timedelta(days=30)


def test_update_schedule_changes_cadence_and_recomputes_next(db, admin_user):
    row = report_schedule_service.create_schedule(
        db,
        name="daily",
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        cadence="daily",
        created_by_user_id=admin_user.id,
    )
    original_next = row.next_run_at
    updated = report_schedule_service.update_schedule(
        db, schedule_id=row.id, cadence="weekly"
    )
    assert updated.cadence == "weekly"
    assert updated.next_run_at != original_next


def test_delete_schedule_removes_row(db, admin_user):
    row = report_schedule_service.create_schedule(
        db,
        name="ephemeral",
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        cadence="daily",
        created_by_user_id=admin_user.id,
    )
    report_schedule_service.delete_schedule(db, schedule_id=row.id)
    assert report_schedule_service.get_schedule(db, row.id) is None


# ---------------------------------------------------------------------------
# Scheduler tick — fire_due_schedules
# ---------------------------------------------------------------------------


def test_fire_due_creates_system_scheduled_report_run(db, admin_user):
    # Seed a schedule whose next_run_at is in the past so it fires.
    row = report_schedule_service.create_schedule(
        db,
        name="due now",
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        cadence="daily",
        filters_snapshot={"plan_id": 1},
        created_by_user_id=admin_user.id,
        first_run_at=datetime.utcnow() - timedelta(minutes=1),
    )
    db.commit()

    counters = report_schedule_service.fire_due_schedules(db)
    assert counters["fired_succeeded"] == 1

    # next_run_at advanced.
    db.refresh(row)
    assert row.next_run_at > datetime.utcnow()
    assert row.last_run_state == "succeeded"

    # report_runs row exists with triggered_by=system_scheduled.
    run = db.query(ReportRun).filter(ReportRun.id == row.last_run_id).one()
    assert run.triggered_by == "system_scheduled"
    assert run.report_kind == "patch_executions"
    assert run.state == "succeeded"
    assert run.row_count is not None


def test_fire_due_is_idempotent(db, admin_user):
    report_schedule_service.create_schedule(
        db,
        name="due now",
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        cadence="daily",
        created_by_user_id=admin_user.id,
        first_run_at=datetime.utcnow() - timedelta(minutes=1),
    )
    db.commit()
    first = report_schedule_service.fire_due_schedules(db)
    second = report_schedule_service.fire_due_schedules(db)
    assert first["fired_succeeded"] == 1
    assert second["fired_succeeded"] == 0


def test_fire_due_skips_disabled(db, admin_user):
    row = report_schedule_service.create_schedule(
        db,
        name="disabled",
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        cadence="daily",
        enabled=False,
        created_by_user_id=admin_user.id,
        first_run_at=datetime.utcnow() - timedelta(minutes=1),
    )
    db.commit()
    counters = report_schedule_service.fire_due_schedules(db)
    assert counters["fired_succeeded"] == 0
    db.refresh(row)
    assert row.last_run_id is None


def test_fire_due_records_failed_run_on_dispatcher_error(db, admin_user):
    # patch_reboot_queues requires an integer execution_id in the
    # filters_snapshot; omitting it triggers the dispatcher to raise.
    row = report_schedule_service.create_schedule(
        db,
        name="bad",
        report_kind=report_run_service.REPORT_KIND_PATCH_REBOOT_QUEUES,
        cadence="daily",
        filters_snapshot={},  # missing required execution_id
        created_by_user_id=admin_user.id,
        first_run_at=datetime.utcnow() - timedelta(minutes=1),
    )
    db.commit()
    counters = report_schedule_service.fire_due_schedules(db)
    assert counters["fired_failed"] == 1
    db.refresh(row)
    assert row.last_run_state == "failed"
    # next_run_at still advanced so the bad config does not loop.
    assert row.next_run_at > datetime.utcnow()
    run = db.query(ReportRun).filter(ReportRun.id == row.last_run_id).one()
    assert run.state == "failed"
    assert run.error_message is not None


# ---------------------------------------------------------------------------
# Route GET / list / RBAC
# ---------------------------------------------------------------------------


def test_list_schedules_route_returns_rows(authed_client, db, admin_user):
    report_schedule_service.create_schedule(
        db,
        name="daily test",
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        cadence="daily",
        created_by_user_id=admin_user.id,
    )
    db.commit()
    res = authed_client.get("/reports/schedules")
    assert res.status_code == 200, res.text
    body = res.json()
    assert any(item["report_kind"] == "patch_executions" for item in body["items"])
    assert body["total"] >= 1


def test_list_schedules_route_filters_by_kind(authed_client, db, admin_user):
    report_schedule_service.create_schedule(
        db,
        name="a",
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        cadence="daily",
        created_by_user_id=admin_user.id,
    )
    report_schedule_service.create_schedule(
        db,
        name="b",
        report_kind=report_run_service.REPORT_KIND_COMPLIANCE_REMEDIATION_REQUESTS,
        cadence="weekly",
        created_by_user_id=admin_user.id,
    )
    db.commit()
    res = authed_client.get(
        "/reports/schedules", params={"report_kind": "patch_executions"}
    )
    assert res.status_code == 200
    body = res.json()
    assert all(r["report_kind"] == "patch_executions" for r in body["items"])


def test_list_schedules_route_rejects_bad_kind(authed_client):
    res = authed_client.get("/reports/schedules", params={"report_kind": "not_a_kind"})
    assert res.status_code == 422


def test_list_schedules_route_auditor_allowed(client, auditor_user):
    token = _login(client, auditor_user)
    res = client.get("/reports/schedules", headers=_bearer(token))
    assert res.status_code == 200


def test_list_schedules_route_viewer_denied(client, db, seed_roles):
    from app.core.auth import get_password_hash
    from app.db.models import User

    viewer = User(
        username="viewertest-sched",
        email="viewertest-sched@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    viewer.roles.append(seed_roles["viewer"])
    db.add(viewer)
    db.commit()
    token = _login(client, viewer)
    res = client.get("/reports/schedules", headers=_bearer(token))
    assert res.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Route POST / PATCH / DELETE — write RBAC
# ---------------------------------------------------------------------------


def test_create_schedule_route_admin(authed_client, admin_user):
    res = authed_client.post(
        "/reports/schedules",
        json={
            "name": "weekly remediation",
            "report_kind": "compliance_remediation_requests",
            "cadence": "weekly",
            "filters_snapshot": {"state": "approved"},
            "format": "csv",
        },
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["name"] == "weekly remediation"
    assert body["cadence"] == "weekly"
    assert body["created_by_user_id"] == admin_user.id


def test_create_schedule_route_auditor_denied(client, auditor_user):
    token = _login(client, auditor_user)
    res = client.post(
        "/reports/schedules",
        headers=_bearer(token),
        json={
            "name": "blocked",
            "report_kind": "patch_executions",
            "cadence": "daily",
        },
    )
    assert res.status_code in (401, 403)


def test_create_schedule_route_rejects_bad_cadence(authed_client):
    res = authed_client.post(
        "/reports/schedules",
        json={
            "name": "bad",
            "report_kind": "patch_executions",
            "cadence": "hourly",
        },
    )
    assert res.status_code == 422


def test_patch_schedule_route_admin_updates_enabled(authed_client, db, admin_user):
    row = report_schedule_service.create_schedule(
        db,
        name="will disable",
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        cadence="daily",
        created_by_user_id=admin_user.id,
    )
    db.commit()
    res = authed_client.patch(
        f"/reports/schedules/{row.id}",
        json={"enabled": False},
    )
    assert res.status_code == 200
    assert res.json()["enabled"] is False


def test_delete_schedule_route_admin(authed_client, db, admin_user):
    row = report_schedule_service.create_schedule(
        db,
        name="will delete",
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        cadence="daily",
        created_by_user_id=admin_user.id,
    )
    db.commit()
    res = authed_client.delete(f"/reports/schedules/{row.id}")
    assert res.status_code == 204
    assert report_schedule_service.get_schedule(db, row.id) is None


def test_patch_schedule_route_404_on_unknown(authed_client):
    res = authed_client.patch("/reports/schedules/9999999", json={"enabled": False})
    assert res.status_code == 404


def test_patch_schedule_route_empty_body_returns_422(authed_client, db, admin_user):
    row = report_schedule_service.create_schedule(
        db,
        name="x",
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        cadence="daily",
        created_by_user_id=admin_user.id,
    )
    db.commit()
    res = authed_client.patch(f"/reports/schedules/{row.id}", json={})
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# Slice 5a fix coverage — atomic race + invalid date filter validation.
# ---------------------------------------------------------------------------


def test_fire_due_concurrent_claim_only_one_run(db, admin_user):
    """Slice 5a P1 fix: two scheduler ticks that both enumerate the
    same due row must not both fire. Simulate the race by snapshotting
    the schedule's ``next_run_at`` (so two ``fire_due_schedules``
    invocations see the same pre-claim value) and proving only one
    succeeded ``ReportRun`` row is persisted for the due window.
    """
    schedule = report_schedule_service.create_schedule(
        db,
        name="race target",
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        cadence="daily",
        created_by_user_id=admin_user.id,
        first_run_at=datetime.utcnow() - timedelta(minutes=1),
    )
    db.commit()

    # Drive two concurrent sessions that both load the same due row
    # before either commits. Each session opens its own DB session
    # via the test engine so the ORM identity maps are independent.
    from sqlalchemy.orm import sessionmaker

    # PRA-170: match production SessionLocal(autoflush=False) so this
    # multi-session race-condition test exercises the same flush
    # semantics as prod.
    Session = sessionmaker(bind=db.bind, autoflush=False, expire_on_commit=False)
    session_a = Session()
    session_b = Session()
    try:
        # Both sessions see the same pre-claim next_run_at via their
        # own enumeration inside fire_due_schedules.
        counter_a = report_schedule_service.fire_due_schedules(session_a)
        counter_b = report_schedule_service.fire_due_schedules(session_b)
    finally:
        session_a.close()
        session_b.close()

    assert counter_a["fired_succeeded"] + counter_b["fired_succeeded"] == 1
    # The other call either skipped (lost the race) or saw no due
    # rows on second look — either way it must NOT have fired again.
    assert counter_a["fired_failed"] == 0
    assert counter_b["fired_failed"] == 0

    # Confirm exactly one succeeded ReportRun row exists for this
    # schedule's due window.
    succeeded_runs = (
        db.query(ReportRun)
        .filter(ReportRun.report_kind == "patch_executions")
        .filter(ReportRun.triggered_by == "system_scheduled")
        .filter(ReportRun.state == "succeeded")
        .all()
    )
    assert len(succeeded_runs) == 1


def test_create_schedule_rejects_malformed_date_filter(db, admin_user):
    """Slice 5a P2 fix: a malformed date string in filters_snapshot
    must fail validation at create time rather than silently widen
    the export to the default review window."""
    with pytest.raises(report_schedule_service.ReportScheduleError) as exc_info:
        report_schedule_service.create_schedule(
            db,
            name="bad-date",
            report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
            cadence="daily",
            filters_snapshot={"started_after": "not-a-date"},
            created_by_user_id=admin_user.id,
        )
    assert "started_after" in str(exc_info.value)


def test_update_schedule_rejects_malformed_date_filter(db, admin_user):
    """Slice 5a P2 fix: same validation applies to update."""
    row = report_schedule_service.create_schedule(
        db,
        name="will-break",
        report_kind=report_run_service.REPORT_KIND_COMPLIANCE_REMEDIATION_REQUESTS,
        cadence="weekly",
        created_by_user_id=admin_user.id,
    )
    with pytest.raises(report_schedule_service.ReportScheduleError) as exc_info:
        report_schedule_service.update_schedule(
            db,
            schedule_id=row.id,
            filters_snapshot={"created_before": "yesterday"},
        )
    assert "created_before" in str(exc_info.value)


def test_fire_due_fails_run_on_legacy_bad_date_filter(db, admin_user):
    """Slice 5a P2 fix: even legacy rows that bypass the CRUD
    validation (e.g. inserted before the fix) must fail loudly at
    tick time rather than silently default to the broad window.

    We simulate that by writing a malformed filter directly through
    the ORM (bypassing ``_bounded_filters``)."""
    row = ReportSchedule(
        name="legacy bad",
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        cadence="daily",
        filters_snapshot={"started_after": "garbage"},
        format="csv",
        enabled=True,
        next_run_at=datetime.utcnow() - timedelta(minutes=1),
        created_by=admin_user.id,
    )
    db.add(row)
    db.commit()

    counters = report_schedule_service.fire_due_schedules(db)
    assert counters["fired_failed"] == 1
    assert counters["fired_succeeded"] == 0

    db.refresh(row)
    assert row.last_run_state == "failed"
    failed = db.query(ReportRun).filter(ReportRun.id == row.last_run_id).one()
    assert failed.state == "failed"
    assert "started_after" in (failed.error_message or "")


def test_fire_due_fails_run_on_remediation_bad_date_filter(db, admin_user):
    """Same validation applies to a compliance/remediation kind so
    the coverage spans at least one patch + one
    compliance/remediation report."""
    row = ReportSchedule(
        name="rem bad",
        report_kind=report_run_service.REPORT_KIND_COMPLIANCE_REMEDIATION_REQUESTS,
        cadence="weekly",
        filters_snapshot={"created_after": "nope"},
        format="csv",
        enabled=True,
        next_run_at=datetime.utcnow() - timedelta(minutes=1),
        created_by=admin_user.id,
    )
    db.add(row)
    db.commit()

    counters = report_schedule_service.fire_due_schedules(db)
    assert counters["fired_failed"] == 1

    db.refresh(row)
    assert row.last_run_state == "failed"
    failed = db.query(ReportRun).filter(ReportRun.id == row.last_run_id).one()
    assert "created_after" in (failed.error_message or "")
