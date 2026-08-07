"""PRA-161 slice 1e — smart-group ``patch.*`` predicate tests.

Covers:

* Validation of every new field (`patch.resolution_kind`,
  `patch.effective_policy_slug`, `patch.has_effective_policy`,
  `patch.policy_requires_approval`, `patch.rollout_cadence`).
* Evaluation against each resolver outcome (direct_host /
  static_group / smart_group / fleet_default / no_policy / conflict),
  including the null-FALSE rule for policy-specific fields.
* Cycle guard: a smart group whose rule references ``patch.*``
  cannot be bound as a patch-policy smart-group target.
* Recompute hooks: representative direct-host, fleet-default, and
  smart-group binding mutations refresh ``patch.*`` smart group
  membership.
"""

from __future__ import annotations

import json

import pytest

from app.db.models import Credential, Group, SmartGroup, SmartGroupMembership, System
from app.services import patch_policy_service, smart_group_service
from app.services.patch_policy_service import PatchPolicyError
from app.services.smart_group_service import RuleValidationError

# -- Fixtures ---------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="patch-pred-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="patch-pred-test-cred",
        auth_method="password",
        username="root",
        vault_path="x",
    )
    db.add(c)
    db.flush()
    return c


@pytest.fixture
def host(db, seed_distro, static_group, credentials) -> System:
    s = System(
        hostname="patch-pred-host.example.com",
        ip_address="10.0.0.50",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=static_group.id,
        credentials_id=credentials.id,
    )
    db.add(s)
    db.flush()
    return s


def _make_policy(db, admin_user, slug, *, enabled=True, fleet_default=False, **kw):
    p = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind=kw.pop("scope_kind", "security_only"),
        enabled=enabled,
        **kw,
    )
    if fleet_default:
        p.is_fleet_default = True
        db.commit()
        db.refresh(p)
    return p


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


# -- Validation -------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    [
        "patch.resolution_kind",
        "patch.effective_policy_slug",
        "patch.has_effective_policy",
        "patch.policy_requires_approval",
        "patch.rollout_cadence",
    ],
)
def test_patch_fields_in_catalog(field):
    assert field in smart_group_service.ALL_FIELDS
    assert field in smart_group_service.PATCH_FIELDS


@pytest.mark.parametrize(
    "kind",
    [
        "direct_host",
        "static_group",
        "smart_group",
        "fleet_default",
        "no_policy",
        "conflict",
    ],
)
def test_validate_resolution_kind_accepts_locked_values(kind):
    smart_group_service.validate_rule(
        {"field": "patch.resolution_kind", "op": "in", "value": [kind]}
    )


def test_validate_resolution_kind_rejects_typo():
    with pytest.raises(RuleValidationError) as ei:
        smart_group_service.validate_rule(
            {
                "field": "patch.resolution_kind",
                "op": "in",
                "value": ["host"],  # typo for "direct_host"
            }
        )
    assert "patch.resolution_kind" in str(ei.value)


@pytest.mark.parametrize("cad", ["immediate", "staged"])
def test_validate_rollout_cadence_accepts_locked_values(cad):
    smart_group_service.validate_rule(
        {"field": "patch.rollout_cadence", "op": "in", "value": [cad]}
    )


def test_validate_rollout_cadence_rejects_typo():
    with pytest.raises(RuleValidationError):
        smart_group_service.validate_rule(
            {
                "field": "patch.rollout_cadence",
                "op": "in",
                "value": ["nightly"],
            }
        )


def test_validate_has_effective_policy_requires_bool():
    smart_group_service.validate_rule(
        {"field": "patch.has_effective_policy", "op": "eq", "value": True}
    )
    with pytest.raises(RuleValidationError):
        smart_group_service.validate_rule(
            {"field": "patch.has_effective_policy", "op": "eq", "value": "true"}
        )


def test_validate_policy_slug_requires_string():
    smart_group_service.validate_rule(
        {"field": "patch.effective_policy_slug", "op": "eq", "value": "weekly"}
    )
    with pytest.raises(RuleValidationError):
        smart_group_service.validate_rule(
            {"field": "patch.effective_policy_slug", "op": "eq", "value": 1}
        )


def test_rule_references_patch_walks_tree():
    rule_yes = {
        "op": "and",
        "rules": [
            {"field": "hostname", "op": "eq", "value": "x"},
            {
                "op": "or",
                "rules": [
                    {
                        "field": "patch.resolution_kind",
                        "op": "in",
                        "value": ["fleet_default"],
                    }
                ],
            },
        ],
    }
    rule_no = {"field": "hostname", "op": "eq", "value": "patch.disguised"}
    assert smart_group_service.rule_references_patch(json.dumps(rule_yes)) is True
    assert smart_group_service.rule_references_patch(rule_yes) is True
    # The string "patch." appears in rule_no's value but no field
    # actually starts with patch. — the parse-then-walk is the
    # correctness boundary, the substring is just a fast-path skip.
    assert smart_group_service.rule_references_patch(rule_no) is False


# -- Evaluation per tier -----------------------------------------------------


def test_eval_resolution_kind_no_policy(db, host):
    rule = {
        "field": "patch.resolution_kind",
        "op": "in",
        "value": ["no_policy"],
    }
    matches = smart_group_service.evaluate(rule, db)
    assert host.id in matches


def test_eval_resolution_kind_fleet_default(db, admin_user, host):
    _make_policy(db, admin_user, "fleet-pred", fleet_default=True)
    rule = {
        "field": "patch.resolution_kind",
        "op": "in",
        "value": ["fleet_default"],
    }
    matches = smart_group_service.evaluate(rule, db)
    assert host.id in matches


def test_eval_resolution_kind_direct_host(db, admin_user, host):
    p = _make_policy(db, admin_user, "direct-pred")
    patch_policy_service.bind_host(
        db, policy_id=p.id, system_id=host.id, actor_user_id=admin_user.id
    )
    rule = {
        "field": "patch.resolution_kind",
        "op": "in",
        "value": ["direct_host"],
    }
    matches = smart_group_service.evaluate(rule, db)
    assert host.id in matches


def test_eval_resolution_kind_conflict(db, admin_user, host):
    """Two distinct policies bound directly to the same host
    surface as ``resolution_kind = conflict`` — the resolver raises
    ``EffectivePolicyConflict`` and the bulk-index builder catches
    it per-host so smart-group evaluation does not crash."""
    p1 = _make_policy(db, admin_user, "conf-1")
    p2 = _make_policy(db, admin_user, "conf-2")
    patch_policy_service.bind_host(
        db, policy_id=p1.id, system_id=host.id, actor_user_id=admin_user.id
    )
    patch_policy_service.bind_host(
        db, policy_id=p2.id, system_id=host.id, actor_user_id=admin_user.id
    )

    rule = {
        "field": "patch.resolution_kind",
        "op": "in",
        "value": ["conflict"],
    }
    matches = smart_group_service.evaluate(rule, db)
    assert host.id in matches


def test_eval_effective_policy_slug_eq(db, admin_user, host):
    p = _make_policy(db, admin_user, "named-pred")
    patch_policy_service.bind_host(
        db, policy_id=p.id, system_id=host.id, actor_user_id=admin_user.id
    )
    rule = {
        "field": "patch.effective_policy_slug",
        "op": "eq",
        "value": "named-pred",
    }
    matches = smart_group_service.evaluate(rule, db)
    assert host.id in matches


def test_eval_has_effective_policy_true(db, admin_user, host):
    _make_policy(db, admin_user, "fleet-yes", fleet_default=True)
    rule = {"field": "patch.has_effective_policy", "op": "eq", "value": True}
    matches = smart_group_service.evaluate(rule, db)
    assert host.id in matches


def test_eval_rollout_cadence_staged(db, admin_user, host):
    # Slice 3 P1 guard: staged policies must start disabled. Bind an
    # enabled ring + flip enabled=True via update_policy to reach the
    # effective state this predicate test requires.
    from app.services import patch_ring_service

    p = _make_policy(
        db, admin_user, "staged-pred", rollout_cadence="staged", enabled=False
    )
    ring = patch_ring_service.create_ring(
        db,
        actor_user_id=admin_user.id,
        slug="staged-pred-ring",
        name="staged-pred-ring",
        sort_order=1,
    )
    patch_policy_service.bind_policy_ring(
        db, policy_id=p.id, ring_id=ring.id, actor_user_id=admin_user.id
    )
    patch_policy_service.update_policy(
        db, p.id, {"enabled": True}, actor_user_id=admin_user.id
    )
    patch_policy_service.bind_host(
        db, policy_id=p.id, system_id=host.id, actor_user_id=admin_user.id
    )
    rule = {
        "field": "patch.rollout_cadence",
        "op": "in",
        "value": ["staged"],
    }
    matches = smart_group_service.evaluate(rule, db)
    assert host.id in matches


def test_eval_requires_approval_true(db, admin_user, host):
    p = _make_policy(db, admin_user, "approval-pred", requires_approval=True)
    patch_policy_service.bind_host(
        db, policy_id=p.id, system_id=host.id, actor_user_id=admin_user.id
    )
    rule = {
        "field": "patch.policy_requires_approval",
        "op": "eq",
        "value": True,
    }
    matches = smart_group_service.evaluate(rule, db)
    assert host.id in matches


# -- null-FALSE behavior on no_policy / conflict ----------------------------


def test_no_policy_does_not_match_slug_eq(db, host):
    rule = {
        "field": "patch.effective_policy_slug",
        "op": "eq",
        "value": "anything",
    }
    matches = smart_group_service.evaluate(rule, db)
    assert host.id not in matches


def test_no_policy_does_not_match_slug_neq(db, host):
    """Negative arm must also miss no_policy hosts (null-FALSE rule)."""
    rule = {
        "field": "patch.effective_policy_slug",
        "op": "neq",
        "value": "anything",
    }
    matches = smart_group_service.evaluate(rule, db)
    assert host.id not in matches


def test_no_policy_does_not_match_requires_approval_either_arm(db, host):
    rule_true = {
        "field": "patch.policy_requires_approval",
        "op": "eq",
        "value": True,
    }
    rule_false = {
        "field": "patch.policy_requires_approval",
        "op": "eq",
        "value": False,
    }
    assert host.id not in smart_group_service.evaluate(rule_true, db)
    assert host.id not in smart_group_service.evaluate(rule_false, db)


def test_conflict_does_not_match_slug_or_cadence(db, admin_user, host):
    p1 = _make_policy(db, admin_user, "c1")
    p2 = _make_policy(db, admin_user, "c2")
    patch_policy_service.bind_host(
        db, policy_id=p1.id, system_id=host.id, actor_user_id=admin_user.id
    )
    patch_policy_service.bind_host(
        db, policy_id=p2.id, system_id=host.id, actor_user_id=admin_user.id
    )
    slug_rule = {
        "field": "patch.effective_policy_slug",
        "op": "eq",
        "value": "c1",
    }
    cad_rule = {
        "field": "patch.rollout_cadence",
        "op": "in",
        "value": ["immediate"],
    }
    assert host.id not in smart_group_service.evaluate(slug_rule, db)
    assert host.id not in smart_group_service.evaluate(cad_rule, db)


def test_no_policy_resolution_kind_matches_in_no_policy(db, host):
    """Sanity: the explicit way to match no_policy hosts — operators
    need this to build "needs a policy" smart groups."""
    rule = {
        "field": "patch.resolution_kind",
        "op": "in",
        "value": ["no_policy"],
    }
    assert host.id in smart_group_service.evaluate(rule, db)


# -- Cycle guard ------------------------------------------------------------


def test_cycle_guard_rejects_patch_referencing_smart_group(db, admin_user):
    p = _make_policy(db, admin_user, "guarded")
    sg = _make_smart_group(
        db,
        name="patch-aware",
        rule={
            "field": "patch.resolution_kind",
            "op": "in",
            "value": ["no_policy"],
        },
    )
    db.commit()

    with pytest.raises(PatchPolicyError) as ei:
        patch_policy_service.bind_smart_group(
            db,
            policy_id=p.id,
            smart_group_id=sg.id,
            actor_user_id=admin_user.id,
        )
    msg = str(ei.value)
    assert "patch.*" in msg
    assert "feedback loop" in msg


def test_cycle_guard_allows_non_patch_smart_group(db, admin_user, host):
    p = _make_policy(db, admin_user, "non-cycle")
    sg = _make_smart_group(
        db,
        name="hostname-only",
        rule={"field": "hostname", "op": "eq", "value": host.hostname},
    )
    db.commit()
    # Should NOT raise.
    binding = patch_policy_service.bind_smart_group(
        db,
        policy_id=p.id,
        smart_group_id=sg.id,
        actor_user_id=admin_user.id,
    )
    assert binding.smart_group_id == sg.id


# -- Recompute hooks --------------------------------------------------------


def test_bind_host_triggers_patch_recompute(db, admin_user, host):
    """A direct-host bind should refresh cached membership of every
    enabled patch.* smart group. Build a "no_policy" smart group, bind
    a policy directly, and assert the cached membership drops the
    host."""
    sg = _make_smart_group(
        db,
        name="no-policy-watch",
        rule={
            "field": "patch.resolution_kind",
            "op": "in",
            "value": ["no_policy"],
        },
    )
    db.commit()
    smart_group_service.recompute_membership(db, sg.id)
    members_before = {
        m.system_id
        for m in db.query(SmartGroupMembership).filter(
            SmartGroupMembership.smart_group_id == sg.id
        )
    }
    assert host.id in members_before

    # Direct-bind the host to a policy — host now resolves direct_host,
    # not no_policy. The bind hook should refresh the smart group.
    p = _make_policy(db, admin_user, "now-bound")
    patch_policy_service.bind_host(
        db,
        policy_id=p.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )

    members_after = {
        m.system_id
        for m in db.query(SmartGroupMembership).filter(
            SmartGroupMembership.smart_group_id == sg.id
        )
    }
    assert host.id not in members_after


def test_set_fleet_default_triggers_patch_recompute(db, admin_user, host):
    sg = _make_smart_group(
        db,
        name="fleet-default-watch",
        rule={
            "field": "patch.resolution_kind",
            "op": "in",
            "value": ["fleet_default"],
        },
    )
    db.commit()
    smart_group_service.recompute_membership(db, sg.id)
    assert (
        db.query(SmartGroupMembership)
        .filter(SmartGroupMembership.smart_group_id == sg.id)
        .count()
        == 0
    )

    p = _make_policy(db, admin_user, "becomes-fleet")
    patch_policy_service.set_fleet_default(db, p.id, actor_user_id=admin_user.id)

    members = {
        m.system_id
        for m in db.query(SmartGroupMembership).filter(
            SmartGroupMembership.smart_group_id == sg.id
        )
    }
    assert host.id in members


def test_bind_smart_group_triggers_patch_recompute(db, admin_user, host):
    """Bind a non-patch smart group containing the host to a patch
    policy — patch.* smart-group cached membership must refresh so a
    `patch.has_effective_policy = true` group picks up the host."""
    target_sg = _make_smart_group(
        db,
        name="hostname-target",
        rule={"field": "hostname", "op": "eq", "value": host.hostname},
    )
    smart_group_service.recompute_membership(db, target_sg.id)

    watcher_sg = _make_smart_group(
        db,
        name="has-policy-watch",
        rule={"field": "patch.has_effective_policy", "op": "eq", "value": True},
    )
    db.commit()
    smart_group_service.recompute_membership(db, watcher_sg.id)
    assert (
        db.query(SmartGroupMembership)
        .filter(SmartGroupMembership.smart_group_id == watcher_sg.id)
        .count()
        == 0
    )

    # Now bind a policy via the smart-group target — the host should
    # become "has_effective_policy = true" via the smart_group tier.
    p = _make_policy(db, admin_user, "smart-bound")
    patch_policy_service.bind_smart_group(
        db,
        policy_id=p.id,
        smart_group_id=target_sg.id,
        actor_user_id=admin_user.id,
    )

    members = {
        m.system_id
        for m in db.query(SmartGroupMembership).filter(
            SmartGroupMembership.smart_group_id == watcher_sg.id
        )
    }
    assert host.id in members


def test_membership_change_on_patch_binder_refreshes_dependent_patch_groups(
    db, admin_user, host, seed_distro, static_group, credentials
):
    """Slice 1e-a regression: when a non-patch
    smart group that is bound to a patch policy changes membership,
    dependent ``patch.*`` smart groups must refresh — even though no
    patch-policy mutation occurred.

    Setup:
      * `target_sg` — non-patch smart group, rule matches a hostname
        prefix. Initially contains only `host`.
      * Patch policy `bound-via-sg` is bound to `target_sg`. So
        `host` resolves via the smart_group tier.
      * `watcher_sg` — patch.* smart group filtering on
        ``patch.has_effective_policy = true``. Initial membership is
        {host} after a recompute.

    Trigger:
      * Add a brand new host whose hostname matches the prefix and
        force ``recompute_membership(target_sg)``. The new host now
        joins `target_sg`, and via the binding, the resolver returns
        the policy via `smart_group` for the new host.

    Lock:
      * After the recompute returns, `watcher_sg`'s cached membership
        must include the new host without any patch-policy mutation
        having occurred. Without the fix, `recompute_membership` only
        refreshed profile-binder dependents, so the new host would
        stay missing from `watcher_sg` until the next 5-min sweep.
    """
    # Build the non-patch binder smart group (matches by hostname prefix)
    target_sg = _make_smart_group(
        db,
        name="hostname-prefix-binder",
        rule={
            "field": "hostname",
            "op": "contains",
            "value": "patch-pred-host",
        },
    )
    smart_group_service.recompute_membership(db, target_sg.id)
    assert host.id in {
        m.system_id
        for m in db.query(SmartGroupMembership).filter(
            SmartGroupMembership.smart_group_id == target_sg.id
        )
    }

    # Bind the policy via the (non-patch) smart group.
    p = _make_policy(db, admin_user, "bound-via-sg")
    patch_policy_service.bind_smart_group(
        db,
        policy_id=p.id,
        smart_group_id=target_sg.id,
        actor_user_id=admin_user.id,
    )

    # patch.* watcher; initial membership picks up the existing host.
    watcher_sg = _make_smart_group(
        db,
        name="has-policy-watch-2",
        rule={"field": "patch.has_effective_policy", "op": "eq", "value": True},
    )
    db.commit()
    smart_group_service.recompute_membership(db, watcher_sg.id)
    members_before = {
        m.system_id
        for m in db.query(SmartGroupMembership).filter(
            SmartGroupMembership.smart_group_id == watcher_sg.id
        )
    }
    assert host.id in members_before

    # Add a brand new host that matches the binder's hostname rule.
    new_host = System(
        hostname="patch-pred-host-new.example.com",
        ip_address="10.0.0.51",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=static_group.id,
        credentials_id=credentials.id,
    )
    db.add(new_host)
    db.commit()
    db.refresh(new_host)

    # Membership change happens here. NO patch-policy mutation runs.
    # The fix in recompute_membership must detect target_sg is a
    # patch binder and follow on with recompute_patch_groups, which
    # then refreshes watcher_sg.
    smart_group_service.recompute_membership(db, target_sg.id)

    members_after = {
        m.system_id
        for m in db.query(SmartGroupMembership).filter(
            SmartGroupMembership.smart_group_id == watcher_sg.id
        )
    }
    assert new_host.id in members_after, (
        "watcher_sg cached membership did not refresh when the patch-binder "
        "smart group's membership changed; recompute_membership() must "
        "trigger recompute_patch_groups(db) for patch-binder smart groups."
    )


def test_recompute_patch_groups_only_touches_patch_groups(db):
    """``recompute_patch_groups`` must not touch smart groups whose
    rule does not reference ``patch.*``."""
    non_patch = _make_smart_group(
        db,
        name="non-patch",
        rule={"field": "hostname", "op": "eq", "value": "anything"},
    )
    patch_aware = _make_smart_group(
        db,
        name="patch-aware-2",
        rule={
            "field": "patch.resolution_kind",
            "op": "in",
            "value": ["no_policy"],
        },
    )
    db.commit()
    touched = smart_group_service.recompute_patch_groups(db)
    assert touched == 1  # only patch_aware
