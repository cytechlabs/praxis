"""PRA-156 #3c: smart-group lifecycle.* predicates + recompute hooks.

Pins the locked semantics:
  * lifecycle.* uses its OWN namespace, NOT facts.*. Missing/stale
    facts collapse to lifecycle.status="unknown" — a real value that
    `in ["unknown"]` matches and `not_in ["supported"]` includes.
  * lifecycle.days_to_eol is NULL for unknown hosts; numeric
    predicates against it follow standard SQL three-valued logic
    (operators wanting unknown hosts must use lifecycle.status).
  * Validation rejects unknown lifecycle.status values up-front.
  * Ingest-time recompute fires lifecycle-group hook AND fact-group
    hook (lifecycle depends on facts; an upsert can move a host
    across a lifecycle threshold).
  * Daily lifecycle recompute (today moves) re-evaluates lifecycle
    groups even without a facts upsert.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta

import pytest

from app.db.models import (
    Credential,
    DistroLifecycle,
    Group,
    HostFacts,
    SmartGroup,
    System,
)
from app.services import facts_service, lifecycle_service, smart_group_service

# ---------------------------------------------------------------- fixtures


@pytest.fixture
def lifecycle_seed(db):
    """Wipe + reseed distro_lifecycle with rows the verdict matrix
    needs. Same pattern as test_pra156_lifecycle_service.
    """
    db.query(DistroLifecycle).delete()
    db.flush()
    today = datetime.utcnow().date()
    rows = [
        # Comfortably supported.
        DistroLifecycle(
            distro_id="ubuntu",
            release="22.04",
            eol_date=today + timedelta(days=400),
            support_kind="standard",
            source="endoflife.date",
            as_of=today,
        ),
        # Approaching window (30d).
        DistroLifecycle(
            distro_id="debian",
            release="12",
            eol_date=today + timedelta(days=30),
            support_kind="standard",
            source="endoflife.date",
            as_of=today,
        ),
        # Unsupported.
        DistroLifecycle(
            distro_id="ubuntu",
            release="18.04",
            eol_date=today - timedelta(days=365),
            support_kind="standard",
            source="endoflife.date",
            as_of=today,
        ),
    ]
    for r in rows:
        db.add(r)
    db.commit()
    return rows


@pytest.fixture
def fleet(db, seed_distro, lifecycle_seed):
    """A four-host fleet covering every lifecycle status:

    - h_supported: ubuntu 22.04, fresh facts.
    - h_approaching: debian 12, fresh facts.
    - h_unsupported: ubuntu 18.04, fresh facts.
    - h_unknown_missing: no host_facts row at all.
    """
    g = Group(name="pra156-3c", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="cred-pra156-3c", auth_method="ssh_key", username="root")
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

    h_supported = _mk("supported.example.com", "10.0.2.1")
    h_approaching = _mk("approaching.example.com", "10.0.2.2")
    h_unsupported = _mk("unsupported.example.com", "10.0.2.3")
    h_unknown_missing = _mk("unknown.example.com", "10.0.2.4")

    fresh_at = datetime.utcnow() - timedelta(minutes=5)
    db.add_all(
        [
            HostFacts(
                system_id=h_supported.id,
                schema_version=1,
                collected_at=fresh_at,
                source_transport="ssh",
                distro_id_facts="ubuntu",
                distro_release="22.04",
            ),
            HostFacts(
                system_id=h_approaching.id,
                schema_version=1,
                collected_at=fresh_at,
                source_transport="ssh",
                distro_id_facts="debian",
                distro_release="12",
            ),
            HostFacts(
                system_id=h_unsupported.id,
                schema_version=1,
                collected_at=fresh_at,
                source_transport="ssh",
                distro_id_facts="ubuntu",
                distro_release="18.04",
            ),
            # h_unknown_missing intentionally has NO host_facts row.
        ]
    )
    db.commit()
    return {
        "supported": h_supported,
        "approaching": h_approaching,
        "unsupported": h_unsupported,
        "unknown": h_unknown_missing,
    }


# ---------------------------------------------------------------- validation


def test_validate_rejects_unknown_lifecycle_status_value():
    """Typoed status values would silently match nothing — fail at
    save time so operators catch it immediately."""
    rule = {
        "field": "lifecycle.status",
        "op": "in",
        "value": ["approaching"],  # typo: should be "approaching-eol"
    }
    with pytest.raises(smart_group_service.RuleValidationError) as excinfo:
        smart_group_service.validate_rule(rule)
    assert "lifecycle.status" in str(excinfo.value)


def test_validate_rejects_bool_for_lifecycle_days_to_eol():
    """isinstance(True, int) is True in Python — same trap as facts.*
    numeric validators (PRA-155 #2a-α). Bool must be rejected."""
    rule = {"field": "lifecycle.days_to_eol", "op": "lt", "value": True}
    with pytest.raises(smart_group_service.RuleValidationError):
        smart_group_service.validate_rule(rule)


def test_validate_accepts_valid_lifecycle_rules():
    smart_group_service.validate_rule(
        {"field": "lifecycle.status", "op": "in", "value": ["unknown", "unsupported"]}
    )
    smart_group_service.validate_rule(
        {"field": "lifecycle.days_to_eol", "op": "lt", "value": 30}
    )


# ---------------------------------------------------------------- evaluate


def test_lifecycle_status_in_supported(db, fleet):
    rule = {"field": "lifecycle.status", "op": "in", "value": ["supported"]}
    matches = set(smart_group_service.evaluate(rule, db))
    assert matches == {fleet["supported"].id}


def test_lifecycle_status_in_unknown_includes_missing_facts(db, fleet):
    """Locked semantics: unknown is a real value. A host with NO
    host_facts row matches `in ["unknown"]` — this is the saved-view
    filter source-of-truth for the unknown bucket."""
    rule = {"field": "lifecycle.status", "op": "in", "value": ["unknown"]}
    matches = set(smart_group_service.evaluate(rule, db))
    assert fleet["unknown"].id in matches


def test_lifecycle_status_in_multiple(db, fleet):
    """Combined approaching-eol + unsupported pulls both fleet hosts."""
    rule = {
        "field": "lifecycle.status",
        "op": "in",
        "value": ["approaching-eol", "unsupported"],
    }
    matches = set(smart_group_service.evaluate(rule, db))
    assert matches == {fleet["approaching"].id, fleet["unsupported"].id}


def test_lifecycle_status_not_in_supported_includes_unknown(db, fleet):
    """Locked semantics differ from facts.*: the negative arm of a
    lifecycle predicate INCLUDES unknown hosts because unknown is a
    real value, not a null fall-through."""
    rule = {"field": "lifecycle.status", "op": "not_in", "value": ["supported"]}
    matches = set(smart_group_service.evaluate(rule, db))
    assert fleet["unknown"].id in matches
    assert fleet["approaching"].id in matches
    assert fleet["unsupported"].id in matches
    assert fleet["supported"].id not in matches


def test_lifecycle_days_to_eol_lt(db, fleet):
    """Numeric predicate matches the approaching host (30d) but not
    the supported host (400d) or any unknown/unsupported."""
    rule = {"field": "lifecycle.days_to_eol", "op": "lt", "value": 90}
    matches = set(smart_group_service.evaluate(rule, db))
    # approaching is 30d out (< 90); unsupported is negative (also < 90).
    assert fleet["approaching"].id in matches
    assert fleet["unsupported"].id in matches
    assert fleet["supported"].id not in matches
    # Unknown host has days_to_eol=None — predicate's NULL semantics
    # exclude it from both arms (operators must use lifecycle.status).
    assert fleet["unknown"].id not in matches


def test_lifecycle_days_to_eol_eq_does_not_match_unknown(db, fleet):
    """Direct null-vs-numeric proof: unknown hosts (days_to_eol=None)
    don't match `eq 0`, `eq -1`, or any other numeric value — even
    though their status equals 'unknown'."""
    for value in [0, -1, 30, 9999]:
        rule = {"field": "lifecycle.days_to_eol", "op": "eq", "value": value}
        matches = set(smart_group_service.evaluate(rule, db))
        assert fleet["unknown"].id not in matches


def test_lifecycle_combined_with_facts(db, fleet):
    """Mixed-namespace rule: lifecycle.status="supported" AND
    facts.distro_id="ubuntu" should compile both paths and AND
    them together. Only h_supported matches both."""
    rule = {
        "op": "and",
        "rules": [
            {"field": "lifecycle.status", "op": "in", "value": ["supported"]},
            {"field": "facts.distro_id", "op": "in", "value": ["ubuntu"]},
        ],
    }
    matches = set(smart_group_service.evaluate(rule, db))
    assert matches == {fleet["supported"].id}


# ---------------------------------------------------------------- bulk index


def test_compute_for_all_systems_covers_every_system(db, fleet):
    """Every system gets an index entry, including hosts with no
    host_facts row (status="unknown")."""
    index = lifecycle_service.compute_for_all_systems(db)
    for h in fleet.values():
        assert h.id in index, f"system {h.id} missing from lifecycle index"
    assert index[fleet["supported"].id].status == "supported"
    assert index[fleet["approaching"].id].status == "approaching-eol"
    assert index[fleet["unsupported"].id].status == "unsupported"
    assert index[fleet["unknown"].id].status == "unknown"


def test_compute_for_all_systems_today_param_drives_verdict(db, fleet):
    """Pass a fixed today to drive a host past its EOL deterministically."""
    # Approaching host (debian 12, EOL today+30) — pass today=eol+1
    # to push it into unsupported.
    far_future = datetime.utcnow().date() + timedelta(days=31)
    index = lifecycle_service.compute_for_all_systems(db, today=far_future)
    assert index[fleet["approaching"].id].status == "unsupported"


# ---------------------------------------------------------------- recompute hooks


def test_rule_references_lifecycle_walks_tree():
    rule = {
        "op": "and",
        "rules": [
            {"field": "hostname", "op": "eq", "value": "x"},
            {
                "op": "or",
                "rules": [
                    {
                        "field": "lifecycle.status",
                        "op": "in",
                        "value": ["unsupported"],
                    },
                ],
            },
        ],
    }
    assert smart_group_service.rule_references_lifecycle(rule) is True


def test_rule_references_lifecycle_returns_false_for_non_lifecycle():
    rule = {
        "op": "and",
        "rules": [
            {"field": "hostname", "op": "eq", "value": "x"},
            {"field": "facts.distro_id", "op": "in", "value": ["ubuntu"]},
        ],
    }
    assert smart_group_service.rule_references_lifecycle(rule) is False


def test_rule_references_lifecycle_fast_path_substring():
    """String input that lacks the substring returns False without
    parsing — fast path avoids json.loads on hot recompute paths."""
    no_lifecycle = '{"field":"hostname","op":"eq","value":"x"}'
    assert smart_group_service.rule_references_lifecycle(no_lifecycle) is False


def test_recompute_lifecycle_groups_for_system_skips_non_lifecycle(db, fleet):
    """A group whose rule has no lifecycle predicate must NOT be
    recomputed by the lifecycle hook."""
    facts_only = SmartGroup(
        name="facts-only-pra156-3c",
        rule_json='{"field":"facts.distro_id","op":"in","value":["ubuntu"]}',
        enabled=True,
    )
    db.add(facts_only)
    db.commit()
    touched = smart_group_service.recompute_lifecycle_groups_for_system(
        db, fleet["supported"].id
    )
    assert touched == 0


def test_recompute_lifecycle_groups_for_system_touches_lifecycle_groups(db, fleet):
    lifecycle_grp = SmartGroup(
        name="lifecycle-grp-pra156-3c",
        rule_json='{"field":"lifecycle.status","op":"in","value":["unsupported"]}',
        enabled=True,
    )
    db.add(lifecycle_grp)
    db.commit()
    touched = smart_group_service.recompute_lifecycle_groups_for_system(
        db, fleet["unsupported"].id
    )
    assert touched == 1


def test_facts_ingest_fires_lifecycle_recompute(db, fleet):
    """An ingest with status="upserted" fires BOTH the facts.* AND the
    lifecycle.* recompute hooks. Proven by creating a lifecycle group
    that starts with stale membership, running an ingest, and
    confirming the cached membership now reflects the live verdict."""
    lifecycle_grp = SmartGroup(
        name="lifecycle-ingest-pra156-3c",
        rule_json='{"field":"lifecycle.status","op":"in","value":["supported"]}',
        enabled=True,
    )
    db.add(lifecycle_grp)
    db.commit()

    # Ingest a facts row for a previously-empty host (h_unknown).
    # Pre-ingest: h_unknown is unknown. Post-ingest: should become
    # supported (matches the group).
    facts_service.ingest(
        db,
        system_id=fleet["unknown"].id,
        payload={
            "schema_version": 1,
            "collected_at": (datetime.utcnow() - timedelta(minutes=1)).isoformat(),
            "distro_id": "ubuntu",
            "distro_release": "22.04",
            "cpu_cores": 4,
        },
        source_transport="ssh",
    )

    members = set(smart_group_service.members(db, lifecycle_grp.id))
    # h_supported was already supported; h_unknown became supported
    # only after the ingest fired the lifecycle recompute hook.
    assert fleet["unknown"].id in members
    assert fleet["supported"].id in members


def test_recompute_dependent_groups_dedupes_mixed_predicate(db, fleet):
    """A group whose rule mixes facts.* AND lifecycle.* must be
    recomputed ONCE per ingest, not twice. Verified via a recompute
    spy: combined helper calls ``recompute_membership`` once per
    matched group regardless of how many namespaces the rule
    touches."""
    mixed = SmartGroup(
        name="mixed-namespaces",
        rule_json=(
            '{"op":"and","rules":['
            '{"field":"facts.distro_id","op":"in","value":["ubuntu"]},'
            '{"field":"lifecycle.status","op":"in","value":["supported"]}'
            "]}"
        ),
        enabled=True,
    )
    facts_only = SmartGroup(
        name="facts-only-mix",
        rule_json='{"field":"facts.distro_id","op":"in","value":["ubuntu"]}',
        enabled=True,
    )
    lifecycle_only = SmartGroup(
        name="lifecycle-only-mix",
        rule_json='{"field":"lifecycle.status","op":"in","value":["supported"]}',
        enabled=True,
    )
    db.add_all([mixed, facts_only, lifecycle_only])
    db.commit()

    call_counts: dict = {}
    real_recompute = smart_group_service.recompute_membership

    def spy_recompute(db_arg, group_id):
        call_counts[group_id] = call_counts.get(group_id, 0) + 1
        return real_recompute(db_arg, group_id)

    import unittest.mock as _mock

    with _mock.patch.object(
        smart_group_service, "recompute_membership", side_effect=spy_recompute
    ):
        touched = smart_group_service.recompute_dependent_groups_for_system(
            db, fleet["supported"].id
        )

    assert touched == 3
    # Each of the three groups is recomputed exactly once.
    assert call_counts.get(mixed.id) == 1
    assert call_counts.get(facts_only.id) == 1
    assert call_counts.get(lifecycle_only.id) == 1


def test_recompute_lifecycle_groups_daily_pass(db, fleet):
    """Simulate the daily pass: the helper iterates every enabled
    group whose rule references lifecycle.* and recomputes
    membership. Mixed groups (facts only, lifecycle only, lifecycle
    nested inside an OR) all behave correctly."""
    facts_only = SmartGroup(
        name="facts-only-daily",
        rule_json='{"field":"facts.distro_id","op":"in","value":["ubuntu"]}',
        enabled=True,
    )
    lifecycle_simple = SmartGroup(
        name="lifecycle-simple-daily",
        rule_json='{"field":"lifecycle.status","op":"in","value":["unsupported"]}',
        enabled=True,
    )
    lifecycle_nested = SmartGroup(
        name="lifecycle-nested-daily",
        rule_json=(
            '{"op":"or","rules":['
            '{"field":"lifecycle.status","op":"in","value":["unknown"]},'
            '{"field":"hostname","op":"eq","value":"never-matches"}'
            "]}"
        ),
        enabled=True,
    )
    db.add_all([facts_only, lifecycle_simple, lifecycle_nested])
    db.commit()

    touched = smart_group_service.recompute_lifecycle_groups(db)
    assert touched == 2  # the two lifecycle groups; facts_only skipped

    assert set(smart_group_service.members(db, lifecycle_simple.id)) == {
        fleet["unsupported"].id
    }
    assert set(smart_group_service.members(db, lifecycle_nested.id)) == {
        fleet["unknown"].id
    }
