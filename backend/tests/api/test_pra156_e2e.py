"""PRA-156 #3e-d: end-to-end pipeline tests.

Bundles the slice-level units into wires-connect paths that drift
first if anything in the lifecycle stack is broken end to end.

  1. ``test_e2e_facts_to_lifecycle_to_dashboard_to_emitter`` — ingest
     facts → per-host /lifecycle verdict → smart-group membership
     reflecting lifecycle.status → /lifecycle/summary bucket counts
     → /lifecycle/systems bucket members → emitter fires correct
     events.
     Anchors:  FactsService.ingest (#3c trigger),
               LifecycleService.compute (#3a-α + #3e-a override),
               smart-group lifecycle.* compile (#3c),
               GET /systems/{id}/lifecycle (#3b),
               GET /lifecycle/summary + /lifecycle/systems (#3d),
               lifecycle_emitter_service.emit_for_all_systems (#3e-c).

  2. ``test_e2e_override_resets_emitter_threshold_sequence`` — host
     starts approaching → emitter fires 90+30 → operator adds an
     override pushing EOL out → membership/verdict flips to supported
     → emitter no-ops → operator pulls override back inside the 90-day
     window → emitter fires fresh against the new effective_eol_date.
     Proves the dedup key includes effective_eol_date and the override
     path threads through every consumer.

Both tests use the FastAPI TestClient (authed) for the API surfaces
that operators see, and direct service calls for the facts ingest +
emitter (those have no operator-facing endpoints in PRA-156).
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.models import (
    Credential,
    DistroLifecycle,
    DistroLifecycleOverride,
    Group,
    LifecycleNotificationState,
    SmartGroup,
    SmartGroupMembership,
    System,
)
from app.services import facts_service, lifecycle_emitter_service, smart_group_service


@pytest.fixture
def lifecycle_seed(db):
    db.query(LifecycleNotificationState).delete()
    db.query(DistroLifecycleOverride).delete()
    db.query(DistroLifecycle).delete()
    db.flush()
    today = datetime.utcnow().date()
    db.add(
        DistroLifecycle(
            distro_id="debian",
            release="12",
            eol_date=today + timedelta(days=30),  # approaching
            support_kind="standard",
            source="endoflife.date",
            as_of=today,
        )
    )
    db.add(
        DistroLifecycle(
            distro_id="ubuntu",
            release="22.04",
            eol_date=today + timedelta(days=400),  # supported
            support_kind="standard",
            source="endoflife.date",
            as_of=today,
        )
    )
    db.commit()


@pytest.fixture
def host_supported(db, seed_distro):
    g = Group(name="pra156-e2e", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="cred-pra156-e2e", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    s = System(
        hostname="supported.example.com",
        ip_address="10.0.8.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    db.commit()
    return s


def _make_smart_group(db, *, name, rule):
    sg = SmartGroup(name=name, rule_json=rule, enabled=True)
    db.add(sg)
    db.commit()
    return sg


# ---------------------------------------------------------------- pipe


def test_e2e_facts_to_lifecycle_to_dashboard_to_emitter(
    authed_client, db, host_supported, lifecycle_seed
):
    """Ingest facts → per-host lifecycle verdict via API → smart-group
    membership → fleet summary + bucket members → emitter fires the
    expected events."""
    sg_approaching = _make_smart_group(
        db,
        name="approaching-e2e",
        rule='{"field":"lifecycle.status","op":"in","value":["approaching-eol"]}',
    )
    sg_supported = _make_smart_group(
        db,
        name="supported-e2e",
        rule='{"field":"lifecycle.status","op":"in","value":["supported"]}',
    )

    # Step 1: ingest debian 12 facts → host should be approaching-eol.
    result = facts_service.ingest(
        db,
        system_id=host_supported.id,
        payload={
            "schema_version": 1,
            "collected_at": (datetime.utcnow() - timedelta(minutes=2)).isoformat(),
            "distro_id": "debian",
            "distro_release": "12",
            "cpu_cores": 2,
        },
        source_transport="ssh",
    )
    assert result.status == "upserted"

    # Step 2: per-host /lifecycle returns approaching-eol.
    body = authed_client.get(f"/systems/{host_supported.id}/lifecycle").json()
    assert body["status"] == "approaching-eol"
    assert body["freshness"] == "fresh"
    assert body["days_to_eol"] is not None and 0 < body["days_to_eol"] <= 90

    # Step 3: smart-group membership reflects the verdict (the ingest
    # hook fires recompute_dependent_groups_for_system per #3c).
    approaching_members = set(smart_group_service.members(db, sg_approaching.id))
    supported_members = set(smart_group_service.members(db, sg_supported.id))
    assert host_supported.id in approaching_members
    assert host_supported.id not in supported_members

    # Step 4: fleet summary counts include the host in approaching_eol.
    summary = authed_client.get("/lifecycle/summary").json()
    assert summary["counts"]["approaching_eol"] >= 1

    # Step 5: bucket-members endpoint returns the host id (truth via
    # smart_group_service.evaluate, locked in #3d).
    bucket = authed_client.get("/lifecycle/systems?status=approaching-eol").json()
    assert host_supported.id in bucket["system_ids"]

    # Step 6: emitter fires 90-day + 30-day approaching events
    # exactly once. send_alert is exercised live (no mock) — the
    # test DB has no alert_configs so delivery no-ops, but the
    # dedup state IS recorded per the lock semantics.
    fired = lifecycle_emitter_service.emit_for_all_systems(db)
    fired_for_host = {(t, n) for sid, t, n in fired if sid == host_supported.id}
    assert ("host_eol_approaching", 90) in fired_for_host
    assert ("host_eol_approaching", 30) in fired_for_host
    assert ("host_eol_approaching", 7) not in fired_for_host  # 30d > 7d threshold
    assert all(
        t != "host_eol_reached" for sid, t, n in fired if sid == host_supported.id
    )

    # Step 7: re-run is a no-op (dedup gate).
    second = lifecycle_emitter_service.emit_for_all_systems(db)
    assert all(sid != host_supported.id for sid, _, _ in second)

    # Dedup state rows reflect the firings.
    state_count = (
        db.query(LifecycleNotificationState)
        .filter(LifecycleNotificationState.system_id == host_supported.id)
        .count()
    )
    assert state_count == len(fired_for_host)


# ---------------------------------------------------------------- override


def test_e2e_override_resets_emitter_threshold_sequence(
    authed_client, db, host_supported, lifecycle_seed
):
    """Override extension changes the dedup key (effective_eol_date)
    and resets the threshold sequence end to end."""
    sg = _make_smart_group(
        db,
        name="override-e2e-grp",
        rule='{"field":"hostname","op":"eq","value":"supported.example.com"}',
    )
    # Static membership so override scope filtering hits.
    db.add(SmartGroupMembership(smart_group_id=sg.id, system_id=host_supported.id))
    db.commit()

    # Step 1: ingest debian 12 facts (host approaching-eol at 30d).
    facts_service.ingest(
        db,
        system_id=host_supported.id,
        payload={
            "schema_version": 1,
            "collected_at": (datetime.utcnow() - timedelta(minutes=2)).isoformat(),
            "distro_id": "debian",
            "distro_release": "12",
            "cpu_cores": 2,
        },
        source_transport="ssh",
    )
    first_fires = {
        (t, n)
        for sid, t, n in lifecycle_emitter_service.emit_for_all_systems(db)
        if sid == host_supported.id
    }
    assert ("host_eol_approaching", 90) in first_fires
    assert ("host_eol_approaching", 30) in first_fires

    # Step 2: operator adds an override pushing EOL out 10 years.
    today = datetime.utcnow().date()
    db.add(
        DistroLifecycleOverride(
            scope_type="smart_group",
            scope_id=sg.id,
            distro_id="debian",
            release="12",
            eol_date=today + timedelta(days=3650),
            support_kind="extended",
            source="ext-support-10y",
        )
    )
    db.commit()

    # Verdict via API now reflects the override.
    body = authed_client.get(f"/systems/{host_supported.id}/lifecycle").json()
    assert body["status"] == "supported"
    assert body["support_kind"] == "extended"

    # Emitter no-ops on the new effective_eol_date — host is now
    # well outside every approaching threshold.
    second_fires = [
        (sid, t, n)
        for sid, t, n in lifecycle_emitter_service.emit_for_all_systems(db)
        if sid == host_supported.id
    ]
    assert second_fires == []

    # Step 3: operator REPLACES the override with a tighter one
    # pulling EOL back into the 60-day window. New
    # effective_eol_date again → fresh dedup keys → 90-day
    # approaching fires.
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
    third_fires = {
        (t, n)
        for sid, t, n in lifecycle_emitter_service.emit_for_all_systems(db)
        if sid == host_supported.id
    }
    # 60 days out is inside the 90-day window — fires fresh against
    # the new effective_eol_date even though the original
    # 30-day-out date had already fired this threshold once.
    assert ("host_eol_approaching", 90) in third_fires
