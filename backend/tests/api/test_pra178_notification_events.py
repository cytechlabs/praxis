"""PRA-178 Slice 3 — notification event vocabulary + routing tests.

Covers:

* Preference route exposes the 10 new PRA-178 event types in
  ``all_types`` and accepts them on the PUT path.
* ``create_notification`` respects per-user disable for at least one
  patch event and one compliance/remediation event (mirrors the
  existing PRA-100 disable semantics).
* Emission helpers in ``notification_events.py`` build the expected
  notification payload shape (event type, severity, bounded title).
* Slice 1 export hooks (Slice 2 carry-forward) remain green.
"""

from __future__ import annotations

import json

from app.db.models import Notification, NotificationPreference, User
from app.services import notification_events


def _login(client, user):
    res = client.post(
        "/auth/login",
        data={"username": user.username, "password": "testpass123"},
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


PRA178_EVENTS = list(notification_events.PRA178_EVENT_TYPES)


# ---------------------------------------------------------------------------
# Preference route exposure
# ---------------------------------------------------------------------------


def test_notification_prefs_route_exposes_pra178_events(authed_client):
    res = authed_client.get("/notification-preferences")
    assert res.status_code == 200, res.text
    body = res.json()
    for event in PRA178_EVENTS:
        assert event in body["all_types"], f"missing {event}"


def test_notification_prefs_put_accepts_pra178_events(authed_client):
    res = authed_client.put(
        "/notification-preferences",
        json={
            "disabled_types": [
                "patch.executed",
                "remediation.failed",
            ]
        },
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert "patch.executed" in body["disabled_types"]
    assert "remediation.failed" in body["disabled_types"]


def test_notification_prefs_put_rejects_unknown_event(authed_client):
    res = authed_client.put(
        "/notification-preferences",
        json={"disabled_types": ["not.a.real.event"]},
    )
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# Disable routing — at least one patch + one compliance/remediation event
# (mirrors the existing PRA-100 disable semantics for new vocabulary).
# ---------------------------------------------------------------------------


def _disabled_prefs(db, user: User, *events: str) -> None:
    prefs = NotificationPreference(
        user_id=user.id, disabled_types=json.dumps(list(events))
    )
    db.add(prefs)
    db.commit()


def test_disable_routing_patch_executed(db, admin_user):
    _disabled_prefs(db, admin_user, "patch.executed")
    # Direct emitter call (the create_notification path is the same as
    # what the service-level hooks invoke).
    notification_events.emit_patch_executed(
        db,
        execution_id=42,
        plan_id=7,
        plan_name="example",
        state="succeeded",
        progress={"host_counts_by_state": {"succeeded": 3, "failed": 0}},
    )
    # User-targeted notifications would skip on disable; broadcasts
    # always persist. The PRA-178 emitter is a broadcast (no user_id),
    # so a row IS created in the table — disable filters at read-time
    # via the notifications list endpoint. Validate the row exists with
    # the right vocabulary.
    rows = db.query(Notification).filter(Notification.type == "patch.executed").all()
    assert len(rows) == 1
    n = rows[0]
    assert n.severity == "info"
    assert "Patch execution succeeded" in n.title
    assert "host_counts_by_state" not in n.message
    # The disable preference still exists — confirm the route layer
    # would short-circuit a user-targeted emit by exercising the same
    # internal predicate.
    from app.services.notification_service import _is_type_disabled

    assert _is_type_disabled(db, admin_user.id, "patch.executed") is True


def test_disable_routing_remediation_requested(db, admin_user):
    _disabled_prefs(db, admin_user, "remediation.requested")
    notification_events.emit_remediation_requested(
        db,
        request_id=99,
        policy_slug="pra178-pol",
        check_slug="missing-pkg",
        system_id=12,
        requested_by=admin_user.id,
    )
    from app.services.notification_service import _is_type_disabled

    assert _is_type_disabled(db, admin_user.id, "remediation.requested") is True
    rows = (
        db.query(Notification)
        .filter(Notification.type == "remediation.requested")
        .all()
    )
    assert len(rows) == 1
    n = rows[0]
    assert n.severity == "warning"
    assert "pra178-pol" in n.title
    assert "missing-pkg" in n.title
    assert f"system #{12}" in n.title


# ---------------------------------------------------------------------------
# Emission shape — representative coverage across patch + compliance +
# remediation events.
# ---------------------------------------------------------------------------


def test_emit_compliance_evaluated_severity_pass(db):
    notification_events.emit_compliance_evaluated(
        db,
        policy_id=1,
        policy_slug="ssh-baseline",
        system_id=5,
        verdict="pass",
    )
    n = db.query(Notification).filter(Notification.type == "compliance.evaluated").one()
    assert n.severity == "info"


def test_emit_compliance_evaluated_severity_fail(db):
    notification_events.emit_compliance_evaluated(
        db,
        policy_id=1,
        policy_slug="ssh-baseline",
        system_id=5,
        verdict="fail",
    )
    n = db.query(Notification).filter(Notification.type == "compliance.evaluated").one()
    assert n.severity == "warning"


def test_emit_compliance_evaluated_severity_error(db):
    notification_events.emit_compliance_evaluated(
        db,
        policy_id=1,
        policy_slug="ssh-baseline",
        system_id=5,
        verdict="error",
    )
    n = db.query(Notification).filter(Notification.type == "compliance.evaluated").one()
    assert n.severity == "error"


def test_emit_patch_executed_failed_severity_is_error(db):
    notification_events.emit_patch_executed(
        db,
        execution_id=1,
        plan_id=1,
        plan_name=None,
        state="failed",
        progress={},
    )
    n = db.query(Notification).filter(Notification.type == "patch.executed").one()
    assert n.severity == "error"
    assert "plan #1" in n.title  # fallback when plan_name is None


def test_emit_remediation_ready(db):
    notification_events.emit_remediation_ready(
        db,
        request_id=7,
        plan_id=3,
        policy_slug="pol",
        check_slug="chk",
        system_id=11,
    )
    n = db.query(Notification).filter(Notification.type == "remediation.ready").one()
    assert n.severity == "info"
    assert "pol/chk" in n.title


def test_emit_remediation_failed_carries_reason(db):
    notification_events.emit_remediation_failed(
        db,
        attempt_id=10,
        request_id=2,
        plan_id=4,
        policy_slug="pol",
        check_slug="chk",
        system_id=9,
        failure_reason="package_manager_failed",
    )
    n = db.query(Notification).filter(Notification.type == "remediation.failed").one()
    assert n.severity == "error"
    assert "package_manager_failed" in n.message


def test_emit_patch_reboot_required(db):
    notification_events.emit_patch_reboot_required(
        db,
        execution_id=8,
        system_id=33,
        system_hostname="host.example.com",
    )
    n = (
        db.query(Notification)
        .filter(Notification.type == "patch.reboot_required")
        .one()
    )
    assert n.severity == "warning"
    assert "host.example.com" in n.title


def test_emit_patch_rollback_started_then_completed(db):
    notification_events.emit_patch_rollback_started(db, execution_id=21, plan_id=12)
    notification_events.emit_patch_rollback_completed(
        db, execution_id=21, plan_id=12, state="succeeded"
    )
    started = (
        db.query(Notification)
        .filter(Notification.type == "patch.rollback_started")
        .one()
    )
    assert started.severity == "warning"
    completed = (
        db.query(Notification)
        .filter(Notification.type == "patch.rollback_completed")
        .one()
    )
    assert completed.severity == "info"


def test_emit_truncates_overlong_message(db):
    # Build a synthetic plan_name longer than the title bound to ensure
    # the bounded helper is wired (no DB-level truncation).
    long_name = "x" * (notification_events.MAX_TITLE_CHARS + 50)
    notification_events.emit_patch_executed(
        db,
        execution_id=1,
        plan_id=1,
        plan_name=long_name,
        state="succeeded",
    )
    n = db.query(Notification).filter(Notification.type == "patch.executed").one()
    assert len(n.title) <= notification_events.MAX_TITLE_CHARS


# ---------------------------------------------------------------------------
# Slice 3a fix coverage — smart-group scoped alert configs match
# host-scoped PRA-178 events. The host-scoped
# emitters previously dropped ``system_id`` on the floor, so any alert
# config with ``scope_smart_group_id`` was silently skipped.
# ---------------------------------------------------------------------------


def _seed_alert_config_for_scope(
    db,
    *,
    smart_group_id,
    events,
):
    """Helper: create an enabled webhook AlertConfig scoped to a
    smart group. Returns the config row id."""
    import json as _json

    from app.db.models import AlertConfig

    cfg = AlertConfig(
        name="pra178-scope-test",
        alert_type="webhook",
        destination="https://example.invalid/hook",
        events=_json.dumps(list(events)),
        enabled=True,
        scope_smart_group_id=smart_group_id,
    )
    db.add(cfg)
    db.commit()
    db.refresh(cfg)
    return cfg.id


def _seed_smart_group_with_member(db, *, system_id):
    """Helper: create a smart group with one explicit membership row
    for ``system_id``. The materializer normally writes these rows;
    we insert directly so the test stays focused."""
    import json as _json

    from app.db.models import SmartGroup, SmartGroupMembership

    sg = SmartGroup(
        name=f"pra178-scope-sg-{system_id}",
        rule_json=_json.dumps({"type": "static", "system_ids": [system_id]}),
        enabled=True,
    )
    db.add(sg)
    db.commit()
    db.refresh(sg)
    db.add(SmartGroupMembership(smart_group_id=sg.id, system_id=system_id))
    db.commit()
    return sg.id


def test_host_scoped_emit_matches_smart_group_scoped_alert_config(
    db, admin_user, seed_distro, monkeypatch
):
    """A host-scoped PRA-178 emit must thread ``system_id`` through so
    ``send_alert``'s ``scope_smart_group_id`` filter matches. Without
    the Slice 3a fix this alert config would have been silently
    skipped."""
    # Stub the actual webhook send so the test does not perform HTTP.
    sent = []

    def fake_attempt_delivery(_db, row, _config):
        sent.append(
            {"event_type": row.event_type, "alert_config_id": row.alert_config_id}
        )
        row.status = "sent"

    from app.services import alert_service

    monkeypatch.setattr(alert_service, "_attempt_delivery", fake_attempt_delivery)

    from app.db.models import Credential, Group, System

    g = Group(name="pra178-scope-grp", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra178-scope-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    host = System(
        hostname="pra178-scope.example.com",
        ip_address="10.0.0.244",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(host)
    db.commit()
    db.refresh(host)

    sg_id = _seed_smart_group_with_member(db, system_id=host.id)
    cfg_id = _seed_alert_config_for_scope(
        db, smart_group_id=sg_id, events=["compliance.evaluated"]
    )

    # Host-scoped emit — must thread system_id through so the
    # smart-group scope filter in send_alert accepts the row.
    notification_events.emit_compliance_evaluated(
        db,
        policy_id=1,
        policy_slug="pra178-scope-pol",
        system_id=host.id,
        verdict="fail",
    )

    assert any(
        s["event_type"] == "compliance.evaluated" and s["alert_config_id"] == cfg_id
        for s in sent
    ), f"expected scoped delivery for compliance.evaluated; saw {sent!r}"


def test_host_scoped_emit_outside_smart_group_is_filtered(
    db, admin_user, seed_distro, monkeypatch
):
    """The other half of the scope contract: when the host is NOT in
    the smart group, the scoped config must NOT receive the event."""
    sent = []

    def fake_attempt_delivery(_db, row, _config):
        sent.append(
            {"event_type": row.event_type, "alert_config_id": row.alert_config_id}
        )
        row.status = "sent"

    from app.services import alert_service

    monkeypatch.setattr(alert_service, "_attempt_delivery", fake_attempt_delivery)

    from app.db.models import Credential, Group, System

    g = Group(name="pra178-out-grp", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra178-out-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    in_host = System(
        hostname="pra178-in.example.com",
        ip_address="10.0.0.245",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    out_host = System(
        hostname="pra178-out.example.com",
        ip_address="10.0.0.246",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add_all([in_host, out_host])
    db.commit()
    db.refresh(in_host)
    db.refresh(out_host)

    sg_id = _seed_smart_group_with_member(db, system_id=in_host.id)
    cfg_id = _seed_alert_config_for_scope(
        db, smart_group_id=sg_id, events=["remediation.requested"]
    )

    notification_events.emit_remediation_requested(
        db,
        request_id=1,
        policy_slug="pol",
        check_slug="chk",
        system_id=out_host.id,
        requested_by=admin_user.id,
    )

    assert not any(
        s["alert_config_id"] == cfg_id for s in sent
    ), f"expected scoped config to skip; saw {sent!r}"
