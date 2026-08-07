"""PRA-156 #3e-c: lifecycle notification emitter tests.

Pins the locked behavior:

  * Each (system, event_type, threshold, effective_eol_date)
    combination fires exactly once. Dedup state lives in
    ``lifecycle_notification_state`` and is recorded AFTER the
    emitter calls ``alert_service.send_alert`` — dedup means
    "Praxis emitted the lifecycle event," not "an external
    webhook was successfully delivered."
  * ``host_eol_reached`` fires when ``days_to_eol == 0`` only —
    not when negative. The day-zero firing satisfies the dedup
    key (system, effective_eol_date) for that EOL date.
  * ``host_eol_approaching`` fires for ``0 < days_to_eol <=
    threshold`` for each of {7, 30, 90}. Strict ``> 0`` lower
    bound so day-zero is not double-counted as both approaching
    AND reached.
  * Override extension that moves ``verdict.eol_date`` out resets
    the threshold sequence — new ``effective_eol_date`` ⇒ new
    dedup keys.
  * Unknown verdicts and verdicts without ``eol_date`` are skipped
    entirely.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from unittest.mock import patch

import pytest

from app.db.models import (
    Credential,
    DistroLifecycle,
    DistroLifecycleOverride,
    Group,
    HostFacts,
    LifecycleNotificationState,
    SmartGroup,
    SmartGroupMembership,
    System,
)
from app.services import alert_service, lifecycle_emitter_service


@pytest.fixture
def lifecycle_seed(db):
    """Wipe + seed lifecycle reference data + clear emitter state."""
    db.query(LifecycleNotificationState).delete()
    db.query(DistroLifecycleOverride).delete()
    db.query(DistroLifecycle).delete()
    db.flush()
    today = datetime.utcnow().date()
    db.add(
        DistroLifecycle(
            distro_id="ubuntu",
            release="22.04",
            eol_date=today + timedelta(days=400),
            support_kind="standard",
            source="endoflife.date",
            as_of=today,
        )
    )
    db.add(
        DistroLifecycle(
            distro_id="debian",
            release="12",
            eol_date=today + timedelta(days=30),
            support_kind="standard",
            source="endoflife.date",
            as_of=today,
        )
    )
    db.add(
        DistroLifecycle(
            distro_id="ubuntu",
            release="18.04",
            eol_date=today,  # Day-zero!
            support_kind="standard",
            source="endoflife.date",
            as_of=today,
        )
    )
    db.add(
        DistroLifecycle(
            distro_id="ubuntu",
            release="14.04",
            eol_date=today - timedelta(days=10),  # Already past EOL
            support_kind="standard",
            source="endoflife.date",
            as_of=today,
        )
    )
    db.commit()


def _mk_host(db, seed_distro, hostname, ip, distro_id_facts, distro_release):
    g = db.query(Group).filter(Group.name == "pra156-3e-c").one_or_none() or Group(
        name="pra156-3e-c", description="x"
    )
    if g.id is None:
        db.add(g)
        db.flush()
    cred = db.query(Credential).filter(
        Credential.name == "cred-pra156-3e-c"
    ).one_or_none() or Credential(
        name="cred-pra156-3e-c", auth_method="ssh_key", username="root"
    )
    if cred.id is None:
        db.add(cred)
        db.flush()
    s = System(
        hostname=hostname,
        ip_address=ip,
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    db.add(
        HostFacts(
            system_id=s.id,
            schema_version=1,
            collected_at=datetime.utcnow() - timedelta(minutes=5),
            source_transport="ssh",
            distro_id_facts=distro_id_facts,
            distro_release=distro_release,
        )
    )
    db.commit()
    return s


# ---------------------------------------------------------------- approaching


def test_approaching_fires_when_inside_threshold(db, seed_distro, lifecycle_seed):
    """Debian 12 host has 30 days to EOL. The 90-day and 30-day
    thresholds should both fire (host crossed both)."""
    host = _mk_host(db, seed_distro, "approach.example.com", "10.0.7.1", "debian", "12")
    with patch.object(alert_service, "send_alert") as spy:
        fired = lifecycle_emitter_service.emit_for_all_systems(db)
    events = {(t, n) for sid, t, n in fired if sid == host.id}
    assert ("host_eol_approaching", 90) in events
    assert ("host_eol_approaching", 30) in events
    # 7-day threshold NOT crossed (host has 30 days).
    assert ("host_eol_approaching", 7) not in events
    # send_alert called once per fired event.
    assert spy.call_count == len(fired)


def test_approaching_no_fire_when_outside_window(db, seed_distro, lifecycle_seed):
    """Ubuntu 22.04 host has 400 days to EOL — outside every
    approaching threshold and not at day-zero. No fires."""
    host = _mk_host(db, seed_distro, "ok.example.com", "10.0.7.2", "ubuntu", "22.04")
    fired = lifecycle_emitter_service.emit_for_all_systems(db)
    assert all(sid != host.id for sid, _, _ in fired)


def test_approaching_dedupes_across_runs(db, seed_distro, lifecycle_seed):
    """Second run on the same day (no verdict change) fires nothing
    new — dedup table prevents duplicate notifications."""
    _mk_host(db, seed_distro, "dedup.example.com", "10.0.7.3", "debian", "12")
    first = lifecycle_emitter_service.emit_for_all_systems(db)
    second = lifecycle_emitter_service.emit_for_all_systems(db)
    assert len(first) >= 2  # 90 + 30
    assert second == []


def test_approaching_strict_greater_than_zero_lower_bound(
    db, seed_distro, lifecycle_seed
):
    """Ubuntu 18.04 host is at day-zero (eol_date == today). Locked
    semantics: approaching uses 0 < days_to_eol <= threshold, so
    the approaching event must NOT fire on this host. Only
    host_eol_reached fires (covered by another test)."""
    host = _mk_host(db, seed_distro, "zero.example.com", "10.0.7.4", "ubuntu", "18.04")
    fired = lifecycle_emitter_service.emit_for_all_systems(db)
    approaching = [
        (sid, t, n)
        for sid, t, n in fired
        if sid == host.id and t == "host_eol_approaching"
    ]
    assert approaching == []


# ---------------------------------------------------------------- reached


def test_reached_fires_at_day_zero(db, seed_distro, lifecycle_seed):
    """Ubuntu 18.04 host's EOL is today. host_eol_reached fires
    once with threshold_days=0 (the locked sentinel)."""
    host = _mk_host(
        db, seed_distro, "reached.example.com", "10.0.7.5", "ubuntu", "18.04"
    )
    fired = lifecycle_emitter_service.emit_for_all_systems(db)
    reached = [
        (sid, t, n) for sid, t, n in fired if sid == host.id and t == "host_eol_reached"
    ]
    assert reached == [(host.id, "host_eol_reached", 0)]


def test_reached_does_not_fire_when_already_past_eol(db, seed_distro, lifecycle_seed):
    """Ubuntu 14.04 host is 10 days past EOL — days_to_eol=-10.
    Locked: reached fires at days_to_eol == 0 only. The day-zero
    firing already happened (presumed; for this test there's no
    pre-existing dedup row, so the assertion is just that
    negative days_to_eol does NOT trigger reached on a fresh
    install)."""
    host = _mk_host(db, seed_distro, "past.example.com", "10.0.7.6", "ubuntu", "14.04")
    fired = lifecycle_emitter_service.emit_for_all_systems(db)
    reached = [
        (sid, t, n) for sid, t, n in fired if sid == host.id and t == "host_eol_reached"
    ]
    assert reached == []


def test_reached_dedupes_across_runs(db, seed_distro, lifecycle_seed):
    _mk_host(
        db, seed_distro, "reached-dedup.example.com", "10.0.7.7", "ubuntu", "18.04"
    )
    first = lifecycle_emitter_service.emit_for_all_systems(db)
    second = lifecycle_emitter_service.emit_for_all_systems(db)
    assert any(t == "host_eol_reached" for _, t, _ in first)
    assert second == []


# ---------------------------------------------------------------- skip rules


def test_skips_unknown_verdicts(db, seed_distro, lifecycle_seed):
    """Host with no host_facts row → unknown verdict → emitter
    skips it entirely. No state row created either."""
    g = Group(name="pra156-3e-c-unknown", description="x")
    db.add(g)
    db.flush()
    cred = Credential(
        name="cred-pra156-3e-c-unknown", auth_method="ssh_key", username="root"
    )
    db.add(cred)
    db.flush()
    s = System(
        hostname="unknown.example.com",
        ip_address="10.0.7.8",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.commit()

    fired = lifecycle_emitter_service.emit_for_all_systems(db)
    assert all(sid != s.id for sid, _, _ in fired)
    state = (
        db.query(LifecycleNotificationState)
        .filter(LifecycleNotificationState.system_id == s.id)
        .all()
    )
    assert state == []


def test_skips_when_no_lifecycle_row(db, seed_distro, lifecycle_seed):
    """Host's distro/release isn't seeded — verdict is unknown
    (no_lifecycle_row reason). Same skip behavior."""
    host = _mk_host(db, seed_distro, "norow.example.com", "10.0.7.9", "freebsd", "14")
    fired = lifecycle_emitter_service.emit_for_all_systems(db)
    assert all(sid != host.id for sid, _, _ in fired)


# ---------------------------------------------------------------- override reset


def test_override_extension_resets_threshold_sequence(db, seed_distro, lifecycle_seed):
    """Host fires at 30-day threshold. Operator then extends EOL
    via override → verdict.eol_date changes → effective_eol_date in
    the dedup key changes → the new threshold sequence is fresh.

    Concrete scenario: debian 12 host fires approaching at 90 + 30.
    Operator adds an override pushing EOL out by 10 years. The
    next run sees the new EOL date and fires nothing (host is now
    well outside the 90-day window). Then we add a SECOND override
    that pulls EOL back to 60 days out — this is a brand-new
    effective_eol_date, so the 90-day approaching fires again
    against the new key."""
    host = _mk_host(
        db, seed_distro, "override-reset.example.com", "10.0.7.10", "debian", "12"
    )
    sg = SmartGroup(
        name="override-reset-grp",
        rule_json='{"field":"hostname","op":"eq","value":"x"}',
        enabled=True,
    )
    db.add(sg)
    db.flush()
    db.add(SmartGroupMembership(smart_group_id=sg.id, system_id=host.id))
    db.commit()

    # First run: standard verdict, fires 90 + 30.
    first = lifecycle_emitter_service.emit_for_all_systems(db)
    first_for_host = {(t, n) for sid, t, n in first if sid == host.id}
    assert ("host_eol_approaching", 90) in first_for_host
    assert ("host_eol_approaching", 30) in first_for_host

    # Operator adds an override pushing EOL out 10 years.
    today = datetime.utcnow().date()
    db.add(
        DistroLifecycleOverride(
            scope_type="smart_group",
            scope_id=sg.id,
            distro_id="debian",
            release="12",
            eol_date=today + timedelta(days=3650),
            support_kind="extended",
            source="ext-support",
        )
    )
    db.commit()

    # Second run: new effective_eol_date, no approaching threshold
    # crossed, no fires.
    second = lifecycle_emitter_service.emit_for_all_systems(db)
    second_for_host = [(sid, t, n) for sid, t, n in second if sid == host.id]
    assert second_for_host == []

    # Operator REPLACES the override with one that pulls EOL into
    # the 60-day window. New effective_eol_date again → new
    # dedup keys → 90-day fires fresh.
    db.query(DistroLifecycleOverride).filter(
        DistroLifecycleOverride.scope_id == sg.id
    ).delete()
    db.add(
        DistroLifecycleOverride(
            scope_type="smart_group",
            scope_id=sg.id,
            distro_id="debian",
            release="12",
            eol_date=today + timedelta(days=60),
            support_kind="extended",
            source="ext-support-pulled-in",
        )
    )
    db.commit()
    third = lifecycle_emitter_service.emit_for_all_systems(db)
    third_for_host = {(t, n) for sid, t, n in third if sid == host.id}
    # The 90-day threshold fires against the new effective_eol_date
    # (60 days out is inside 90).
    assert ("host_eol_approaching", 90) in third_for_host


# ---------------------------------------------------------------- alert wiring


def test_emitter_calls_send_alert_with_system_id(db, seed_distro, lifecycle_seed):
    """The emitter passes system_id to send_alert so smart-group
    scoped alert configs (PRA-126) filter correctly. Mock spy
    proves this without exercising the alert delivery path."""
    host = _mk_host(db, seed_distro, "wiring.example.com", "10.0.7.11", "debian", "12")
    with patch.object(alert_service, "send_alert") as spy:
        lifecycle_emitter_service.emit_for_all_systems(db)
    # Find at least one call for our host.
    calls_for_host = [
        c for c in spy.call_args_list if c.kwargs.get("system_id") == host.id
    ]
    assert (
        calls_for_host
    ), "expected at least one send_alert call carrying our system_id"
    # Sanity: event_type matches the locked names.
    event_types = {c.kwargs["event_type"] for c in calls_for_host}
    assert event_types <= {"host_eol_approaching", "host_eol_reached"}


def test_emitter_does_not_record_state_when_send_alert_raises(
    db, seed_distro, lifecycle_seed
):
    """If send_alert genuinely raises (not the swallowed delivery
    failures it normally absorbs), the dedup row is NOT written —
    so the next emitter run will retry. Better to re-fire than to
    silently lose a notification."""
    host = _mk_host(db, seed_distro, "raise.example.com", "10.0.7.12", "debian", "12")
    with patch.object(alert_service, "send_alert", side_effect=RuntimeError("boom")):
        fired = lifecycle_emitter_service.emit_for_all_systems(db)
    assert all(sid != host.id for sid, _, _ in fired)
    state = (
        db.query(LifecycleNotificationState)
        .filter(LifecycleNotificationState.system_id == host.id)
        .all()
    )
    assert state == []


def test_dedup_state_recorded_after_send_alert_returns(db, seed_distro, lifecycle_seed):
    """Lock semantics: dedup means 'Praxis emitted the lifecycle
    event,' not 'external delivery succeeded.' Even if zero
    alert_configs match (send_alert returns None doing nothing),
    the dedup row IS written so the next run doesn't re-fire."""
    host = _mk_host(
        db, seed_distro, "no-configs.example.com", "10.0.7.13", "debian", "12"
    )

    # send_alert with NO matching configs is a no-op that returns
    # None — exactly the case we need to cover. We don't need to
    # mock; this DB has no alert_configs at all.
    fired = lifecycle_emitter_service.emit_for_all_systems(db)
    fired_for_host = [(sid, t, n) for sid, t, n in fired if sid == host.id]
    assert fired_for_host  # at least the 90-day threshold fired

    # Dedup state recorded.
    state = (
        db.query(LifecycleNotificationState)
        .filter(LifecycleNotificationState.system_id == host.id)
        .all()
    )
    assert len(state) == len(fired_for_host)


def test_emitter_writes_to_state_table_not_alert_history_directly(
    db, seed_distro, lifecycle_seed
):
    """LOCKED: the emitter must use the dedup table for 'should we
    fire?', then call send_alert for delivery. It must NOT write
    to alert_history directly. Verified by snapshot — alert_history
    rows after a fire come from send_alert's normal path, not from
    the emitter."""
    from app.db.models import AlertHistory

    host = _mk_host(
        db, seed_distro, "no-history.example.com", "10.0.7.14", "debian", "12"
    )
    history_before = db.query(AlertHistory).count()
    lifecycle_emitter_service.emit_for_all_systems(db)
    history_after = db.query(AlertHistory).count()
    # No alert_configs configured for these event types in the test
    # DB → send_alert finds zero matches → no AlertHistory rows.
    # If the emitter had ANY direct write to AlertHistory, this
    # delta would be non-zero.
    assert history_after == history_before
    # But the dedup table DID get written.
    state = (
        db.query(LifecycleNotificationState)
        .filter(LifecycleNotificationState.system_id == host.id)
        .all()
    )
    assert len(state) > 0
