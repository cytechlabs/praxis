"""PRA-155 #2d: smart-group facts.* predicates + ingest-time recompute.

Pins the locked semantics:
  * facts.* predicate evaluates FALSE when host_facts is missing OR
    the specific column is NULL — including for not_eq / not_in.
  * ingest-time recompute fires ONLY on IngestResult.status='upserted'
    (skip rejected_stale / rejected_invalid_timestamp / noop_empty).
  * recompute_fact_groups_for_system parses rule structure to identify
    facts.* fields; smart groups with no fact dependency are NOT
    touched.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from app.db.models import (
    Credential,
    Group,
    HostFacts,
    SmartGroup,
    SmartGroupMembership,
    System,
)
from app.services import facts_service, smart_group_service

# ---------------------------------------------------------------- fixtures


@pytest.fixture
def fleet(db, seed_distro):
    """Three Active hosts.

    - h_full: has a host_facts row with concrete values.
    - h_partial_null: has a host_facts row but the column under test
      is NULL.
    - h_missing: has NO host_facts row at all.
    """
    g = Group(name="pra155-2d", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="cred-pra155-2d", auth_method="ssh_key", username="root")
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

    h_full = _mk("full.example.com", "10.0.1.1")
    h_partial_null = _mk("partial.example.com", "10.0.1.2")
    h_missing = _mk("missing.example.com", "10.0.1.3")

    # h_full — concrete values across the locked field set.
    db.add(
        HostFacts(
            system_id=h_full.id,
            schema_version=1,
            collected_at=datetime.utcnow() - timedelta(minutes=5),
            source_transport="ssh",
            kernel_version="5.15.0-101-generic",
            distro_id_facts="ubuntu",
            distro_release="22.04",
            cpu_cores=8,
            ram_total_bytes=16 * 1024**3,
            uptime_seconds=86400,
            reboot_required=False,
            package_manager="apt",
            package_manager_version="apt 2.4.10",
            virtualization="kvm",
            cloud_provider="aws",
        )
    )
    # h_partial_null — has a row but every fact column is NULL.
    db.add(
        HostFacts(
            system_id=h_partial_null.id,
            schema_version=1,
            collected_at=datetime.utcnow() - timedelta(minutes=5),
            source_transport="ssh",
        )
    )
    # h_missing — no host_facts row at all.

    db.commit()
    return {"full": h_full, "partial_null": h_partial_null, "missing": h_missing}


def _matches(db, rule):
    return set(smart_group_service.evaluate(rule, db))


# ---------------------------------------------------------------- string


def test_string_eq_only_matches_full_row(db, fleet):
    rule = {"field": "facts.kernel_version", "op": "eq", "value": "5.15.0-101-generic"}
    matched = _matches(db, rule)
    assert matched == {fleet["full"].id}


def test_string_neq_excludes_missing_and_null(db, fleet):
    """Locked semantics: not_eq against missing host_facts or NULL
    column is FALSE — those hosts are NOT in the matching set."""
    rule = {
        "field": "facts.kernel_version",
        "op": "neq",
        "value": "5.15.0-101-generic",
    }
    matched = _matches(db, rule)
    # Only hosts with a kernel_version that is BOTH non-null AND
    # not equal to the value match. h_full has the matching value
    # (excluded), h_partial_null is NULL (excluded), h_missing has
    # no row (excluded). So nothing matches.
    assert matched == set()


def test_string_neq_against_different_value_matches_only_full(db, fleet):
    rule = {
        "field": "facts.kernel_version",
        "op": "neq",
        "value": "6.5.0-test",
    }
    matched = _matches(db, rule)
    # h_full has kernel != "6.5.0-test" → matches.
    # h_partial_null has NULL kernel → does NOT match (locked).
    # h_missing has no row → does NOT match (locked).
    assert matched == {fleet["full"].id}


def test_string_contains(db, fleet):
    rule = {"field": "facts.kernel_version", "op": "contains", "value": "5.15"}
    assert _matches(db, rule) == {fleet["full"].id}


def test_string_regex(db, fleet):
    rule = {"field": "facts.kernel_version", "op": "regex", "value": "^5\\.15"}
    assert _matches(db, rule) == {fleet["full"].id}


# ---------------------------------------------------------------- enum


def test_enum_in_only_matches_full(db, fleet):
    rule = {"field": "facts.distro_id", "op": "in", "value": ["ubuntu", "debian"]}
    assert _matches(db, rule) == {fleet["full"].id}


def test_enum_not_in_excludes_missing_and_null(db, fleet):
    """not_in against missing/null is FALSE — same lock as not_eq."""
    rule = {"field": "facts.distro_id", "op": "not_in", "value": ["ubuntu"]}
    matched = _matches(db, rule)
    # h_full distro_id == "ubuntu" → in the not_in target → excluded.
    # h_partial_null distro_id IS NULL → locked false → excluded.
    # h_missing no row → locked false → excluded.
    assert matched == set()


def test_enum_not_in_against_unrelated_value_matches_only_full(db, fleet):
    rule = {"field": "facts.distro_id", "op": "not_in", "value": ["rhel", "alpine"]}
    matched = _matches(db, rule)
    assert matched == {fleet["full"].id}


def test_enum_in_case_insensitive(db, fleet):
    rule = {"field": "facts.distro_id", "op": "in", "value": ["UBUNTU"]}
    assert _matches(db, rule) == {fleet["full"].id}


# ---------------------------------------------------------------- bool


def test_bool_eq_true_excludes_null_and_missing(db, fleet):
    """h_full has reboot_required=False → not match.
    h_partial_null has NULL → must NOT match (locked).
    h_missing no row → must NOT match."""
    rule = {"field": "facts.reboot_required", "op": "eq", "value": True}
    assert _matches(db, rule) == set()


def test_bool_eq_false_only_matches_explicit_false(db, fleet):
    """eq=false matches only rows where the column IS FALSE — NULL
    columns and missing rows are excluded by the locked semantics."""
    rule = {"field": "facts.reboot_required", "op": "eq", "value": False}
    matched = _matches(db, rule)
    assert matched == {fleet["full"].id}
    assert fleet["partial_null"].id not in matched
    assert fleet["missing"].id not in matched


# ---------------------------------------------------------------- number


def test_number_gt_excludes_null_and_missing(db, fleet):
    rule = {"field": "facts.cpu_cores", "op": "gt", "value": 4}
    matched = _matches(db, rule)
    assert matched == {fleet["full"].id}


def test_number_lt(db, fleet):
    rule = {"field": "facts.cpu_cores", "op": "lt", "value": 16}
    assert _matches(db, rule) == {fleet["full"].id}


def test_number_validator_rejects_boolean_value(db, fleet):
    """``isinstance(True, int)`` is True in Python — without an
    explicit bool guard the validator would happily accept a boolean
    for a numeric facts field, persist the rule, then compile to an
    int-column-vs-bool comparison at evaluate time. Mirror the
    PRA-155 #2a-α sanitizer discipline: reject upfront with a clean
    RuleValidationError so the contract surfaces before persistence."""
    for value in (True, False):
        with pytest.raises(smart_group_service.RuleValidationError):
            smart_group_service.validate_rule(
                {"field": "facts.cpu_cores", "op": "eq", "value": value}
            )
        with pytest.raises(smart_group_service.RuleValidationError):
            smart_group_service.validate_rule(
                {"field": "facts.ram_total_bytes", "op": "gt", "value": value}
            )


def test_number_eq_zero_does_not_match_null(db, fleet):
    """A NULL ram_total_bytes must NOT match eq=0 — null is not zero."""
    rule = {"field": "facts.ram_total_bytes", "op": "eq", "value": 0}
    matched = _matches(db, rule)
    assert fleet["partial_null"].id not in matched


# ---------------------------------------------------------------- compound


def test_facts_predicate_combines_with_existing_fields(db, fleet):
    """Mixing facts.* with existing System fields under and/or works."""
    rule = {
        "op": "and",
        "rules": [
            {"field": "status", "op": "in", "value": ["Active"]},
            {"field": "facts.distro_id", "op": "in", "value": ["ubuntu"]},
        ],
    }
    assert _matches(db, rule) == {fleet["full"].id}


# ---------------------------------------------------------------- rule_references_facts


def test_rule_references_facts_walks_tree():
    rule = {
        "op": "or",
        "rules": [
            {"field": "hostname", "op": "eq", "value": "x"},
            {
                "op": "and",
                "rules": [
                    {"field": "status", "op": "in", "value": ["Active"]},
                    {"field": "facts.cpu_cores", "op": "gt", "value": 4},
                ],
            },
        ],
    }
    assert smart_group_service.rule_references_facts(rule) is True


def test_rule_references_facts_returns_false_for_non_facts_rules():
    rule = {
        "op": "and",
        "rules": [
            {"field": "hostname", "op": "eq", "value": "x"},
            {"field": "status", "op": "in", "value": ["Active"]},
        ],
    }
    assert smart_group_service.rule_references_facts(rule) is False


def test_rule_references_facts_handles_string_input():
    """JSON string fast-path skip should still be correct."""
    no_facts = json.dumps({"field": "hostname", "op": "eq", "value": "x"})
    has_facts = json.dumps({"field": "facts.cpu_cores", "op": "gt", "value": 4})
    assert smart_group_service.rule_references_facts(no_facts) is False
    assert smart_group_service.rule_references_facts(has_facts) is True


def test_rule_references_facts_does_not_match_substring_only():
    """If the substring 'facts.' appears in a string VALUE but no
    field actually starts with 'facts.', the parser-based check
    returns False. The substring check is a fast-path skip, not the
    correctness boundary."""
    sneaky = json.dumps(
        {"field": "hostname", "op": "contains", "value": "facts.example.com"}
    )
    assert smart_group_service.rule_references_facts(sneaky) is False


# ---------------------------------------------------------------- recompute hook


def _make_smart_group(db, *, name, rule):
    sg = SmartGroup(
        name=name,
        rule_json=json.dumps(rule),
        enabled=True,
    )
    db.add(sg)
    db.flush()
    db.commit()
    return sg


def test_ingest_upserted_triggers_scoped_recompute(db, fleet):
    """A successful upsert triggers recompute_fact_groups_for_system,
    which only re-evaluates groups referencing facts.*."""
    sg_facts = _make_smart_group(
        db,
        name="ubuntu-fleet",
        rule={"field": "facts.distro_id", "op": "in", "value": ["ubuntu"]},
    )
    sg_unrelated = _make_smart_group(
        db,
        name="active-only",
        rule={"field": "status", "op": "in", "value": ["Active"]},
    )

    with patch.object(
        smart_group_service,
        "recompute_membership",
        wraps=smart_group_service.recompute_membership,
    ) as recompute_mock:
        result = facts_service.ingest(
            db,
            system_id=fleet["missing"].id,
            payload={
                "schema_version": 1,
                "collected_at": "2026-05-01T12:00:00",
                "distro_id": "ubuntu",
            },
            source_transport="ssh",
        )
    assert result.status == "upserted"
    called_ids = {c.args[1] for c in recompute_mock.mock_calls}
    assert sg_facts.id in called_ids
    # Unrelated groups are NOT recomputed at ingest time.
    assert sg_unrelated.id not in called_ids


def test_ingest_rejected_stale_does_not_recompute(db, fleet):
    """No real change → no recompute."""
    sg = _make_smart_group(
        db,
        name="ubuntu-fleet",
        rule={"field": "facts.distro_id", "op": "in", "value": ["ubuntu"]},
    )
    # Seed an existing fresh row for h_missing.
    facts_service.ingest(
        db,
        system_id=fleet["missing"].id,
        payload={
            "collected_at": "2026-05-01T13:00:00",
            "distro_id": "ubuntu",
        },
        source_transport="ssh",
    )

    with patch.object(smart_group_service, "recompute_membership") as recompute_mock:
        result = facts_service.ingest(
            db,
            system_id=fleet["missing"].id,
            payload={
                "collected_at": "2026-04-30T12:00:00",  # older
                "distro_id": "ubuntu",
            },
            source_transport="ssh",
        )
    assert result.status == "rejected_stale"
    # No recompute fired at all.
    assert recompute_mock.call_count == 0
    # Group still exists; just confirming the patch took.
    assert sg.id is not None


def test_ingest_noop_empty_does_not_recompute(db, fleet):
    """Empty heartbeat poll never triggers recompute."""
    _make_smart_group(
        db,
        name="ubuntu-fleet",
        rule={"field": "facts.distro_id", "op": "in", "value": ["ubuntu"]},
    )
    with patch.object(smart_group_service, "recompute_membership") as recompute_mock:
        result = facts_service.ingest(
            db,
            system_id=fleet["missing"].id,
            payload={},
            source_transport="ssh",
        )
    assert result.status == "noop_empty"
    assert recompute_mock.call_count == 0


def test_ingest_upserted_actually_updates_membership(db, fleet):
    """End-to-end: a smart group that didn't include the host pre-
    ingest should include it post-ingest (membership row materialized)."""
    sg = _make_smart_group(
        db,
        name="has-cpu-cores-gte-4",
        rule={"field": "facts.cpu_cores", "op": "gte", "value": 4},
    )
    # Trigger one recompute to materialize current membership (h_full
    # has cpu_cores=8 which already satisfies the rule).
    smart_group_service.recompute_membership(db, sg.id)
    pre_members = {
        m.system_id
        for m in db.query(SmartGroupMembership).filter_by(smart_group_id=sg.id)
    }
    assert pre_members == {fleet["full"].id}

    # Now ingest cpu_cores=16 for the previously-missing host. The
    # ingest-time hook should recompute and add it to the group.
    facts_service.ingest(
        db,
        system_id=fleet["missing"].id,
        payload={
            "collected_at": "2026-05-01T13:00:00",
            "cpu_cores": 16,
        },
        source_transport="ssh",
    )
    db.expire_all()
    post_members = {
        m.system_id
        for m in db.query(SmartGroupMembership).filter_by(smart_group_id=sg.id)
    }
    assert fleet["missing"].id in post_members
    assert fleet["full"].id in post_members
