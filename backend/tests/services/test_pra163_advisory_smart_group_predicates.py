"""PRA-163 slice 3 — smart-group ``advisory.*`` predicate tests.

Covers:

* Validation of every locked field
  (``advisory.applicable_count`` / ``applicable_critical_count`` /
  ``applicable_high_count`` / ``applicable_security_count`` /
  ``unknown_count`` / ``has_open_advisories``).
* Type/op rejection: numeric fields reject bool values, bool field
  rejects non-bool values.
* ``rule_references_advisory`` walks nested AND/OR/NOT.
* Per-field semantics: each count reflects the right slice of
  ``patch_advisory_host_applicability`` joined to ``patch_advisories``;
  bool reflects ``applicable_count > 0``.
* Multi-host bulk-index correctness with no cross-talk.
* Hosts without any applicability rows produce zero counts and
  ``has_open_advisories=False`` (the absent-row path).
* ``compute_host_applicability`` triggers ``recompute_advisory_groups``
  ONLY when its row delta is non-zero.
* The Slice 2 quiet path (no facts AND no prior rows → no-op
  result.changed=False) does NOT trigger advisory smart-group recompute.
* Non-inheritance of cycle guards: an ``advisory.*`` smart group CAN
  be bound as a patch-policy and as a ring smart-group source
  without raising — proves Slice 3 did not accidentally inherit
  the same-domain ``patch.*`` / ``ring.*`` guards.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

import pytest

from app.db.models import (
    Credential,
    Group,
    HostFacts,
    Package,
    PatchAdvisory,
    PatchAdvisoryHostApplicability,
    SmartGroup,
    System,
)
from app.services import (
    patch_advisory_service,
    patch_policy_service,
    patch_ring_service,
    smart_group_service,
)
from app.services.patch_advisory_service import (
    APPLICABILITY_STATE_APPLICABLE,
    SOURCE_KIND_REDHAT_UPDATEINFO,
    SOURCE_KIND_UBUNTU_USN,
    compute_host_applicability,
    normalize_redhat_updateinfo,
    normalize_ubuntu_usn,
)
from app.services.smart_group_service import (
    ADVISORY_FIELDS,
    RuleValidationError,
    compute_advisory_index,
    rule_references_advisory,
)
from tests.conftest import unique_test_ip

# -- Fixtures ---------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="advisory-pred-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="advisory-pred-test-cred",
        auth_method="password",
        username="root",
        vault_path="x",
    )
    db.add(c)
    db.flush()
    return c


def _make_host(
    db,
    seed_distro,
    static_group,
    credentials,
    *,
    hostname: str,
    distro_id_facts: Optional[str] = "ubuntu",
    distro_release: Optional[str] = "22.04",
    write_facts: bool = True,
):
    s = System(
        hostname=hostname,
        ip_address=unique_test_ip(),
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=static_group.id,
        credentials_id=credentials.id,
    )
    db.add(s)
    db.flush()
    if write_facts:
        db.add(
            HostFacts(
                system_id=s.id,
                schema_version=1,
                collected_at=datetime.utcnow(),
                source_transport="agent",
                distro_id_facts=distro_id_facts,
                distro_release=distro_release,
            )
        )
        db.flush()
    return s


def _add_package(db, system, *, name, version):
    db.add(
        Package(
            system_id=system.id,
            name=name,
            installed_version=version,
            package_type="deb",
        )
    )
    db.flush()


def _import_usn(
    db,
    admin_user,
    *,
    advisory_id: str,
    release_packages: dict,
    severity: str = "High",
):
    raw = {
        "id": advisory_id,
        "title": f"{advisory_id} title",
        "summary": "test",
        "severity": severity,
        "release_packages": release_packages,
    }
    payload = normalize_ubuntu_usn(raw)
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[payload],
        actor_user_id=admin_user.id,
    )


def _make_smart_group(db, *, name, rule, enabled=True) -> SmartGroup:
    sg = SmartGroup(
        name=name,
        description="t",
        rule_json=json.dumps(rule),
        enabled=enabled,
    )
    db.add(sg)
    db.flush()
    return sg


# -- ADVISORY_FIELDS catalog locked --------------------------------------


def test_advisory_fields_catalog_is_locked():
    assert ADVISORY_FIELDS == {
        "advisory.applicable_count",
        "advisory.applicable_critical_count",
        "advisory.applicable_high_count",
        "advisory.applicable_security_count",
        "advisory.unknown_count",
        "advisory.has_open_advisories",
    }


# -- Validator ------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    [
        "advisory.applicable_count",
        "advisory.applicable_critical_count",
        "advisory.applicable_high_count",
        "advisory.applicable_security_count",
        "advisory.unknown_count",
    ],
)
def test_validate_numeric_advisory_field_accepts_int(field):
    smart_group_service.validate_rule({"field": field, "op": "gt", "value": 0})


@pytest.mark.parametrize(
    "field",
    [
        "advisory.applicable_count",
        "advisory.applicable_critical_count",
    ],
)
def test_validate_numeric_advisory_field_rejects_bool(field):
    with pytest.raises(RuleValidationError, match="must be a number"):
        smart_group_service.validate_rule({"field": field, "op": "gt", "value": True})


def test_validate_numeric_advisory_field_rejects_string_op():
    with pytest.raises(RuleValidationError):
        smart_group_service.validate_rule(
            {
                "field": "advisory.applicable_count",
                "op": "contains",
                "value": "1",
            }
        )


def test_validate_has_open_advisories_accepts_bool():
    smart_group_service.validate_rule(
        {"field": "advisory.has_open_advisories", "op": "eq", "value": True}
    )
    smart_group_service.validate_rule(
        {"field": "advisory.has_open_advisories", "op": "eq", "value": False}
    )


def test_validate_has_open_advisories_rejects_non_bool():
    with pytest.raises(RuleValidationError, match="must be boolean"):
        smart_group_service.validate_rule(
            {"field": "advisory.has_open_advisories", "op": "eq", "value": 1}
        )


def test_validate_rejects_unknown_advisory_field():
    with pytest.raises(RuleValidationError):
        smart_group_service.validate_rule(
            {"field": "advisory.bogus", "op": "eq", "value": True}
        )


# -- rule_references_advisory walker -------------------------------------


def test_rule_references_advisory_leaf_match():
    assert (
        rule_references_advisory(
            {"field": "advisory.applicable_count", "op": "gt", "value": 0}
        )
        is True
    )


def test_rule_references_advisory_nested_and_or():
    rule = {
        "op": "and",
        "rules": [
            {"field": "hostname", "op": "contains", "value": "prod"},
            {
                "op": "or",
                "rules": [
                    {
                        "field": "advisory.applicable_critical_count",
                        "op": "gt",
                        "value": 0,
                    },
                    {"field": "patch.has_effective_policy", "op": "eq", "value": True},
                ],
            },
        ],
    }
    assert rule_references_advisory(rule) is True


def test_rule_references_advisory_returns_false_when_unrelated():
    rule = {
        "op": "and",
        "rules": [
            {"field": "hostname", "op": "contains", "value": "prod"},
            {"field": "patch.has_effective_policy", "op": "eq", "value": True},
        ],
    }
    assert rule_references_advisory(rule) is False


def test_rule_references_advisory_handles_string_input():
    raw = json.dumps(
        {"field": "advisory.has_open_advisories", "op": "eq", "value": True}
    )
    assert rule_references_advisory(raw) is True


def test_rule_references_advisory_fast_path_skips_when_substring_absent():
    # No 'advisory.' anywhere → fast-path False without parsing.
    raw = json.dumps({"field": "hostname", "op": "eq", "value": "x"})
    assert rule_references_advisory(raw) is False


# -- Per-field semantics + bulk-index correctness ------------------------


def test_compute_advisory_index_counts_applicable(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="adv-host-applicable.example",
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-PRED-APPLIC-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    index = compute_advisory_index(db)
    facts = index[host.id]
    assert facts.applicable_count == 1
    assert facts.has_open_advisories is True


def test_compute_advisory_index_critical_severity_counted(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="adv-host-crit.example",
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-PRED-CRIT-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
        severity="Critical",
    )
    facts = compute_advisory_index(db)[host.id]
    assert facts.applicable_count == 1
    assert facts.applicable_critical_count == 1
    assert facts.applicable_high_count == 0
    assert facts.applicable_security_count == 1  # USN class is security


def test_compute_advisory_index_high_severity_counted(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="adv-host-high.example"
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-PRED-HIGH-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
        severity="High",
    )
    facts = compute_advisory_index(db)[host.id]
    assert facts.applicable_high_count == 1
    assert facts.applicable_critical_count == 0


def test_compute_advisory_index_security_class_counted(
    db, admin_user, seed_distro, static_group, credentials
):
    """USNs always have advisory_class='security'; an updateinfo
    bugfix should NOT bump applicable_security_count."""
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="adv-host-sec.example",
        distro_id_facts="rhel",
        distro_release="9",
    )
    _add_package(db, host, name="curl", version="7.61.0-1.el9")
    raw = {
        "id": "RHBA-PRED-1",
        "type": "bugfix",
        "severity": "Moderate",
        "title": "curl bugfix",
        "release": "9",
        "distro_id": "rhel",
        "packages": [{"name": "curl", "version": "7.61.1-1.el9"}],
    }
    payload = normalize_redhat_updateinfo(raw)
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_REDHAT_UPDATEINFO,
        payloads=[payload],
        actor_user_id=admin_user.id,
    )
    facts = compute_advisory_index(db)[host.id]
    assert facts.applicable_count == 1
    assert facts.applicable_security_count == 0  # bugfix, not security
    assert facts.applicable_critical_count == 0


def test_compute_advisory_index_unknown_state_counted(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="adv-host-unk.example"
    )
    _add_package(db, host, name="openssl", version="not-a-version")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-PRED-UNK-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    facts = compute_advisory_index(db)[host.id]
    assert facts.unknown_count == 1
    assert facts.applicable_count == 0
    assert facts.has_open_advisories is False


def test_compute_advisory_index_fixed_and_not_applicable_do_not_bump_counts(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="adv-host-fixed.example",
    )
    # openssl already at the fixed version → state=fixed
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.20")
    # USN also names libssl3, not installed → state=not_applicable
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-PRED-NACOUNT-1",
        release_packages={
            "jammy": [
                {"name": "openssl", "version": "3.0.2-0ubuntu1.15"},
                {"name": "libssl3", "version": "3.0.2-0ubuntu1.15"},
            ],
        },
    )
    facts = compute_advisory_index(db)[host.id]
    # fixed + not_applicable rows exist but contribute zero to counts.
    assert facts.applicable_count == 0
    assert facts.unknown_count == 0
    assert facts.has_open_advisories is False


def test_compute_advisory_index_absent_host_has_zero_facts(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="adv-host-absent.example",
    )
    # No packages, no advisories → no applicability rows → zero facts.
    facts = compute_advisory_index(db)[host.id]
    assert facts.applicable_count == 0
    assert facts.applicable_critical_count == 0
    assert facts.applicable_high_count == 0
    assert facts.applicable_security_count == 0
    assert facts.unknown_count == 0
    assert facts.has_open_advisories is False


def test_compute_advisory_index_no_cross_talk(
    db, admin_user, seed_distro, static_group, credentials
):
    h1 = _make_host(
        db, seed_distro, static_group, credentials, hostname="adv-cross-1.example"
    )
    h2 = _make_host(
        db, seed_distro, static_group, credentials, hostname="adv-cross-2.example"
    )
    _add_package(db, h1, name="openssl", version="3.0.2-0ubuntu1.10")
    _add_package(db, h2, name="curl", version="7.81.0-1ubuntu1.15")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-CROSS-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    index = compute_advisory_index(db)
    assert index[h1.id].applicable_count == 1
    assert index[h2.id].applicable_count == 0
    assert index[h1.id].has_open_advisories is True
    assert index[h2.id].has_open_advisories is False


# -- evaluate() end-to-end membership ------------------------------------


def test_evaluate_advisory_predicate_picks_only_applicable_hosts(
    db, admin_user, seed_distro, static_group, credentials
):
    h_match = _make_host(
        db, seed_distro, static_group, credentials, hostname="eval-match.example"
    )
    h_other = _make_host(
        db, seed_distro, static_group, credentials, hostname="eval-other.example"
    )
    _add_package(db, h_match, name="openssl", version="3.0.2-0ubuntu1.10")
    _add_package(db, h_other, name="curl", version="7.81.0-1ubuntu1.15")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-EVAL-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    matched = smart_group_service.evaluate(
        json.dumps({"field": "advisory.applicable_count", "op": "gt", "value": 0}),
        db,
    )
    assert h_match.id in matched
    assert h_other.id not in matched


def test_evaluate_has_open_advisories_eq_false_includes_zero_count_hosts(
    db, admin_user, seed_distro, static_group, credentials
):
    """A host with no applicability rows must match
    ``advisory.has_open_advisories eq False`` because the bulk-index
    fills absent hosts with ``has_open_advisories=False``.
    """
    h_no_apps = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="eval-no-apps.example",
    )
    matched = smart_group_service.evaluate(
        json.dumps(
            {"field": "advisory.has_open_advisories", "op": "eq", "value": False}
        ),
        db,
    )
    assert h_no_apps.id in matched


# -- Recompute hook fires on real delta ----------------------------------


def test_compute_host_applicability_triggers_advisory_recompute_on_change(
    db, admin_user, seed_distro, static_group, credentials, monkeypatch
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="recompute-fire.example"
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")

    calls = {"count": 0}

    def fake_recompute(db_):
        calls["count"] += 1
        return 0

    monkeypatch.setattr(
        smart_group_service, "recompute_advisory_groups", fake_recompute
    )
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-FIRE-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    # The import-side recompute fanout calls compute_host_applicability
    # for the matching host; the recompute hook fires once for the
    # changed host.
    assert calls["count"] >= 1


def test_compute_host_applicability_no_op_does_not_trigger_advisory_recompute(
    db, admin_user, seed_distro, static_group, credentials, monkeypatch
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="recompute-noop.example"
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    # First import to seed applicability rows (this will fire recompute).
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-NOOP-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )

    # Now monkeypatch and run a manual compute_host_applicability with
    # no input changes — must be a no-op (result.changed=False) and
    # MUST NOT fire the smart-group hook.
    calls = {"count": 0}
    monkeypatch.setattr(
        smart_group_service,
        "recompute_advisory_groups",
        lambda db_: calls.__setitem__("count", calls["count"] + 1) or 0,
    )
    result = compute_host_applicability(db, host.id)
    assert not result.changed
    assert calls["count"] == 0


def test_no_facts_with_no_prior_rows_does_not_trigger_advisory_recompute(
    db, admin_user, seed_distro, static_group, credentials, monkeypatch
):
    """Slice 2 quiet path: a host with no facts AND no prior
    applicability rows yields ``host_facts_missing=True`` AND
    ``result.changed=False`` (no rows to clean up). Slice 3 must NOT
    fire the smart-group recompute on this path.
    """
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="recompute-quiet.example",
        write_facts=False,
    )
    calls = {"count": 0}
    monkeypatch.setattr(
        smart_group_service,
        "recompute_advisory_groups",
        lambda db_: calls.__setitem__("count", calls["count"] + 1) or 0,
    )
    result = compute_host_applicability(db, host.id)
    assert result.host_facts_missing is True
    assert not result.changed
    assert calls["count"] == 0


def test_no_facts_with_prior_rows_triggers_advisory_recompute(
    db, admin_user, seed_distro, static_group, credentials, monkeypatch
):
    """Inverse of the quiet path: a host that previously had
    applicability rows but lost its facts (e.g., a stale-facts purge)
    triggers a delta (``rows_removed > 0``) and must fire the
    smart-group recompute hook.
    """
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="recompute-purge.example",
        write_facts=False,
    )
    # Plant a stale applicability row + an advisory it can point to.
    advisory = PatchAdvisory(
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="USN-PURGE-1",
        advisory_class="security",
        severity="high",
        title="x",
        distro_family="debian",
        digest="0" * 64,
    )
    db.add(advisory)
    db.flush()
    db.add(
        PatchAdvisoryHostApplicability(
            system_id=host.id,
            advisory_id=advisory.id,
            package_name="openssl",
            installed_version="3.0.2-0ubuntu1.10",
            required_version="3.0.2-0ubuntu1.15",
            state=APPLICABILITY_STATE_APPLICABLE,
            evaluated_at=datetime.utcnow(),
        )
    )
    db.commit()

    calls = {"count": 0}
    monkeypatch.setattr(
        smart_group_service,
        "recompute_advisory_groups",
        lambda db_: calls.__setitem__("count", calls["count"] + 1) or 0,
    )
    result = compute_host_applicability(db, host.id)
    assert result.host_facts_missing is True
    assert result.rows_removed == 1
    assert result.changed
    assert calls["count"] == 1


# -- Non-inheritance of cycle guards -------------------------------------


def test_advisory_smart_group_can_be_bound_as_ring_smart_group_source(
    db, admin_user, seed_distro, static_group, credentials
):
    """advisory.* smart groups must NOT inherit the ring.* cycle
    guard. Advisory facts derive from independent inputs (HostFacts +
    Package + advisory tables), not from ring membership, so binding
    an advisory.* smart group as a ring source cannot create a
    feedback loop. Slice 3 design lock.
    """
    sg = _make_smart_group(
        db,
        name="adv-ring-binder",
        rule={"field": "advisory.has_open_advisories", "op": "eq", "value": True},
    )
    ring = patch_ring_service.create_ring(
        db,
        actor_user_id=admin_user.id,
        slug="adv-ring-target",
        name="adv-ring-target",
        sort_order=10,
    )
    # Should NOT raise — proves Slice 3 didn't accidentally pull in
    # the ring cycle guard.
    binding = patch_ring_service.bind_smart_group(
        db,
        ring_id=ring.id,
        smart_group_id=sg.id,
        actor_user_id=admin_user.id,
    )
    assert binding is not None


def test_advisory_smart_group_can_be_bound_as_patch_policy_smart_group_source(
    db, admin_user, seed_distro, static_group, credentials
):
    """Same as above for patch-policy bindings. Slice 3 design lock."""
    sg = _make_smart_group(
        db,
        name="adv-patch-binder",
        rule={
            "field": "advisory.applicable_critical_count",
            "op": "gt",
            "value": 0,
        },
    )
    policy = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="adv-patch-target",
        name="adv patch target",
        scope_kind="security_only",
        scope_packages=[],
        reboot_policy="if_required",
        rollout_cadence="immediate",
        failure_policy="continue",
    )
    # Should NOT raise.
    binding = patch_policy_service.bind_smart_group(
        db,
        policy_id=policy.id,
        smart_group_id=sg.id,
        actor_user_id=admin_user.id,
    )
    assert binding is not None
