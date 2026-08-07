"""PRA-156 #3e-a: distro_lifecycle_override tests.

Pins the locked override semantics:

  * Override REPLACES (not extends) the standard-row verdict when
    a host belongs to a smart group with a matching override row.
  * Lookup precedence mirrors the standard row: exact release wins
    over RHEL-family major fallback. Within matching overrides,
    latest eol_date wins, then newest updated_at, then highest id.
  * Override scope is filtered to the host's actual smart-group
    memberships — overrides on groups the host is NOT in must be
    invisible to that host's verdict.
  * Smart-group lifecycle.* predicates pick up override-driven
    verdicts because the bulk index threads memberships through.
  * compute_for_all_systems bulk-loads memberships in a single
    query (no N per-system lookups).
"""

from __future__ import annotations

from datetime import date, datetime, timedelta

import pytest

from app.db.models import (
    Credential,
    DistroLifecycle,
    DistroLifecycleOverride,
    Group,
    HostFacts,
    SmartGroup,
    SmartGroupMembership,
    System,
)
from app.services import lifecycle_service, smart_group_service
from app.services.lifecycle_service import (
    LIFECYCLE_APPROACHING_EOL,
    LIFECYCLE_SUPPORTED,
    LIFECYCLE_UNSUPPORTED,
)


@pytest.fixture
def today() -> date:
    return date(2026, 5, 2)


@pytest.fixture
def lifecycle_seed(db):
    """Single standard row: ubuntu 22.04 EOL ~one year out (in the
    approaching window so override behavior is visible — without an
    override, host is approaching-eol; with an override pushing EOL
    several years out, host becomes supported)."""
    db.query(DistroLifecycle).delete()
    db.query(DistroLifecycleOverride).delete()
    db.flush()
    db.add(
        DistroLifecycle(
            distro_id="ubuntu",
            release="22.04",
            eol_date=date(2026, 6, 1),  # ~30 days out from today
            support_kind="standard",
            source="endoflife.date",
            as_of=date(2026, 5, 2),
        )
    )
    # rhel/9 standard row for the RHEL-family normalization test.
    db.add(
        DistroLifecycle(
            distro_id="rhel",
            release="9",
            eol_date=date(2026, 6, 1),
            support_kind="standard",
            source="endoflife.date",
            as_of=date(2026, 5, 2),
        )
    )
    db.commit()


@pytest.fixture
def smart_group_with_override(db):
    """A smart group + a matching extended-support override that
    pushes ubuntu 22.04 EOL out to 2032."""
    sg = SmartGroup(
        name="ubuntu-pro-customers",
        rule_json='{"field":"hostname","op":"contains","value":"pro"}',
        enabled=True,
    )
    db.add(sg)
    db.flush()
    db.add(
        DistroLifecycleOverride(
            scope_type="smart_group",
            scope_id=sg.id,
            distro_id="ubuntu",
            release="22.04",
            eol_date=date(2032, 6, 1),
            support_kind="extended",
            source="ubuntu-pro-entitlement",
        )
    )
    db.commit()
    return sg


# ---------------------------------------------------------------- override applied


def test_override_replaces_standard_verdict(
    db, today, lifecycle_seed, smart_group_with_override
):
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="22.04",
        today=today,
        freshness="fresh",
        smart_group_ids=[smart_group_with_override.id],
    )
    assert verdict.status == LIFECYCLE_SUPPORTED
    assert verdict.eol_date == date(2032, 6, 1)
    assert verdict.support_kind == "extended"
    assert verdict.source == "ubuntu-pro-entitlement"


def test_override_skipped_when_host_not_in_scoped_group(
    db, today, lifecycle_seed, smart_group_with_override
):
    """Host belongs to a DIFFERENT smart group. Override must not
    apply — verdict comes from the standard row."""
    other_group = SmartGroup(
        name="other-group",
        rule_json='{"field":"hostname","op":"eq","value":"x"}',
        enabled=True,
    )
    db.add(other_group)
    db.commit()
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="22.04",
        today=today,
        freshness="fresh",
        smart_group_ids=[other_group.id],
    )
    assert verdict.status == LIFECYCLE_APPROACHING_EOL
    assert verdict.eol_date == date(2026, 6, 1)
    assert verdict.support_kind == "standard"


def test_no_smart_group_ids_uses_standard_row(db, today, lifecycle_seed):
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="22.04",
        today=today,
        freshness="fresh",
        smart_group_ids=None,
    )
    assert verdict.eol_date == date(2026, 6, 1)
    assert verdict.support_kind == "standard"


# ---------------------------------------------------------------- precedence


def test_multiple_overrides_pick_latest_eol_date(db, today, lifecycle_seed):
    """When two scoped overrides match, latest eol_date wins —
    operator probably wants the longest-supported entitlement."""
    sg1 = SmartGroup(
        name="sg-shorter",
        rule_json='{"field":"hostname","op":"eq","value":"x"}',
        enabled=True,
    )
    sg2 = SmartGroup(
        name="sg-longer",
        rule_json='{"field":"hostname","op":"eq","value":"y"}',
        enabled=True,
    )
    db.add_all([sg1, sg2])
    db.flush()
    db.add(
        DistroLifecycleOverride(
            scope_type="smart_group",
            scope_id=sg1.id,
            distro_id="ubuntu",
            release="22.04",
            eol_date=date(2030, 1, 1),
            support_kind="extended",
            source="sg1",
        )
    )
    db.add(
        DistroLifecycleOverride(
            scope_type="smart_group",
            scope_id=sg2.id,
            distro_id="ubuntu",
            release="22.04",
            eol_date=date(2034, 1, 1),
            support_kind="extended",
            source="sg2",
        )
    )
    db.commit()
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="22.04",
        today=today,
        freshness="fresh",
        smart_group_ids=[sg1.id, sg2.id],
    )
    assert verdict.eol_date == date(2034, 1, 1)
    assert verdict.source == "sg2"


def test_override_exact_release_wins_over_rhel_major_fallback(
    db, today, lifecycle_seed
):
    """When both an exact-release override (rhel 9.4) and a
    major-only override (rhel 9) exist, the exact match wins —
    mirrors the standard-row precedence locked in #3a-α."""
    sg = SmartGroup(
        name="sg-rhel-precedence",
        rule_json='{"field":"hostname","op":"eq","value":"x"}',
        enabled=True,
    )
    db.add(sg)
    db.flush()
    db.add(
        DistroLifecycleOverride(
            scope_type="smart_group",
            scope_id=sg.id,
            distro_id="rhel",
            release="9",
            eol_date=date(2030, 1, 1),
            support_kind="extended",
            source="rhel-major-override",
        )
    )
    db.add(
        DistroLifecycleOverride(
            scope_type="smart_group",
            scope_id=sg.id,
            distro_id="rhel",
            release="9.4",
            eol_date=date(2028, 1, 1),  # Earlier than the major row.
            support_kind="extended",
            source="rhel-94-override",
        )
    )
    db.commit()
    # Host reports rhel 9.4 — exact override wins over the major one
    # even though the major one's eol_date is later. This proves
    # the candidate-list precedence is being honored, not just
    # raw "latest date".
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="rhel",
        distro_release="9.4",
        today=today,
        freshness="fresh",
        smart_group_ids=[sg.id],
    )
    assert verdict.eol_date == date(2028, 1, 1)
    assert verdict.source == "rhel-94-override"


def test_rhel_major_override_applies_when_no_exact(db, today, lifecycle_seed):
    """Without an exact-release override for rhel 9.4, the major-only
    rhel/9 override applies via the same RHEL-family normalization."""
    sg = SmartGroup(
        name="sg-rhel-major-only",
        rule_json='{"field":"hostname","op":"eq","value":"x"}',
        enabled=True,
    )
    db.add(sg)
    db.flush()
    db.add(
        DistroLifecycleOverride(
            scope_type="smart_group",
            scope_id=sg.id,
            distro_id="rhel",
            release="9",
            eol_date=date(2030, 1, 1),
            support_kind="extended",
            source="rhel-major-override",
        )
    )
    db.commit()
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="rhel",
        distro_release="9.4",
        today=today,
        freshness="fresh",
        smart_group_ids=[sg.id],
    )
    assert verdict.eol_date == date(2030, 1, 1)
    assert verdict.support_kind == "extended"


# ---------------------------------------------------------------- bulk index


def test_compute_for_all_systems_threads_memberships(
    db, seed_distro, lifecycle_seed, smart_group_with_override
):
    """A host that's a member of the smart group with an override
    should see the override-driven verdict via the bulk index. A
    sibling host outside the group should NOT."""
    g = Group(name="pra156-3e-a", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="cred-3e-a", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()

    def _mk(hostname, ip):
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
        return s

    pro_host = _mk("pro-host.example.com", "10.0.4.1")
    free_host = _mk("free-host.example.com", "10.0.4.2")
    fresh_at = datetime.utcnow() - timedelta(minutes=5)
    db.add_all(
        [
            HostFacts(
                system_id=pro_host.id,
                schema_version=1,
                collected_at=fresh_at,
                source_transport="ssh",
                distro_id_facts="ubuntu",
                distro_release="22.04",
            ),
            HostFacts(
                system_id=free_host.id,
                schema_version=1,
                collected_at=fresh_at,
                source_transport="ssh",
                distro_id_facts="ubuntu",
                distro_release="22.04",
            ),
        ]
    )
    # Place pro_host in the override-scoped group; free_host stays out.
    db.add(
        SmartGroupMembership(
            smart_group_id=smart_group_with_override.id, system_id=pro_host.id
        )
    )
    db.commit()

    index = lifecycle_service.compute_for_all_systems(db)
    assert index[pro_host.id].eol_date == date(2032, 6, 1)
    assert index[pro_host.id].support_kind == "extended"
    # free_host has no membership → standard row applies → approaching-eol.
    assert index[free_host.id].eol_date == date(2026, 6, 1)
    assert index[free_host.id].support_kind == "standard"


def test_compute_for_all_systems_bulk_loads_memberships_one_query(
    db, seed_distro, lifecycle_seed, smart_group_with_override
):
    """Membership lookup must happen in ONE bulk query, not per-system.
    Verified via a query-count spy on the membership query path."""
    g = Group(name="pra156-3e-a-counts", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="cred-3e-a-counts", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    fresh_at = datetime.utcnow() - timedelta(minutes=5)
    for i in range(5):
        s = System(
            hostname=f"q{i}.example.com",
            ip_address=f"10.0.5.{i + 1}",
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
                collected_at=fresh_at,
                source_transport="ssh",
                distro_id_facts="ubuntu",
                distro_release="22.04",
            )
        )
        db.add(
            SmartGroupMembership(
                smart_group_id=smart_group_with_override.id, system_id=s.id
            )
        )
    db.commit()

    membership_query_count = {"n": 0}
    real_query = db.query

    def spy_query(*args, **kwargs):
        if (
            args
            and len(args) == 2
            and args[0] is SmartGroupMembership.system_id
            and args[1] is SmartGroupMembership.smart_group_id
        ):
            membership_query_count["n"] += 1
        return real_query(*args, **kwargs)

    import unittest.mock as _mock

    with _mock.patch.object(db, "query", side_effect=spy_query):
        lifecycle_service.compute_for_all_systems(db)
    # One bulk membership fetch regardless of how many systems
    # exist. (The per-system compute() calls have their own
    # override lookup queries — those use the override table, not
    # the membership table.)
    assert membership_query_count["n"] == 1


# ---------------------------------------------------------------- predicate path


def test_smart_group_predicate_reflects_override_verdict(
    db, seed_distro, lifecycle_seed, smart_group_with_override
):
    """A lifecycle.status=supported smart-group rule should pick up
    the pro_host even though the standard row alone would put it in
    approaching-eol. This proves overrides flow through the smart-
    group compile path end-to-end."""
    g = Group(name="pra156-3e-a-predicate", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="cred-3e-a-pred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    pro_host = System(
        hostname="pro-pred.example.com",
        ip_address="10.0.6.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(pro_host)
    db.flush()
    db.add(
        HostFacts(
            system_id=pro_host.id,
            schema_version=1,
            collected_at=datetime.utcnow() - timedelta(minutes=5),
            source_transport="ssh",
            distro_id_facts="ubuntu",
            distro_release="22.04",
        )
    )
    db.add(
        SmartGroupMembership(
            smart_group_id=smart_group_with_override.id, system_id=pro_host.id
        )
    )
    db.commit()

    rule = {"field": "lifecycle.status", "op": "in", "value": ["supported"]}
    matches = set(smart_group_service.evaluate(rule, db))
    assert pro_host.id in matches


def test_override_can_make_supported_become_unsupported(
    db, today, lifecycle_seed, smart_group_with_override
):
    """Override doesn't only extend support — an operator could
    record an EARLIER EOL (e.g. internal sunset policy). Verdict
    follows the override regardless of direction."""
    db.query(DistroLifecycleOverride).filter(
        DistroLifecycleOverride.scope_id == smart_group_with_override.id
    ).delete()
    db.add(
        DistroLifecycleOverride(
            scope_type="smart_group",
            scope_id=smart_group_with_override.id,
            distro_id="ubuntu",
            release="22.04",
            eol_date=date(2025, 1, 1),  # Already past today
            support_kind="extended",
            source="internal-sunset",
        )
    )
    db.commit()
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts="ubuntu",
        distro_release="22.04",
        today=today,
        freshness="fresh",
        smart_group_ids=[smart_group_with_override.id],
    )
    assert verdict.status == LIFECYCLE_UNSUPPORTED
    assert verdict.source == "internal-sunset"
