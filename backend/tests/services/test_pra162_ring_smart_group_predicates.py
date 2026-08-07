"""PRA-162 slice 5 — smart-group ``ring.*`` predicate tests.

Covers:

* Validation of every new field (`ring.status`, `ring.source_kind`,
  `ring.effective_slug`, `ring.effective_name`, `ring.has_effective_ring`).
* Evaluation against each Slice 2 resolver outcome (host / group /
  smart_group source kinds, no_ring sentinel, conflict sentinel),
  including the null-FALSE rule for fields that are populated only
  when the resolver returns a single resolved ring.
* Disabled-ring filtering: predicates inherit Slice 2 semantics
  (disabled rings fall through and the resolver decides).
* Cycle guard: a smart group whose rule references ``ring.*`` cannot
  be bound as a ring smart-group target.
* Recompute hooks: ring CRUD enable toggle, ring delete, host /
  group / smart-group bind/unbind all refresh ``ring.*`` smart group
  membership.
* Cascade hook: when a smart group bound as a ring source has its
  membership change, dependent ``ring.*`` smart groups refresh.
"""

from __future__ import annotations

import json

import pytest

from app.db.models import Credential, Group, SmartGroup, SmartGroupMembership, System
from app.services import patch_ring_service, smart_group_service
from app.services.patch_ring_service import PatchRingError
from app.services.smart_group_service import RuleValidationError

# -- Fixtures ---------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="ring-pred-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="ring-pred-test-cred",
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
        hostname="ring-pred-host.example.com",
        ip_address="10.0.0.95",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=static_group.id,
        credentials_id=credentials.id,
    )
    db.add(s)
    db.flush()
    return s


def _make_ring(db, admin_user, slug, *, sort_order, enabled=True):
    return patch_ring_service.create_ring(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        sort_order=sort_order,
        enabled=enabled,
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


# -- Validation -------------------------------------------------------------


def test_validate_ring_status_accepts_locked_values(db):
    smart_group_service.validate_rule(
        {"field": "ring.status", "op": "in", "value": ["resolved"]}
    )
    smart_group_service.validate_rule(
        {"field": "ring.status", "op": "not_in", "value": ["no_ring", "conflict"]}
    )


def test_validate_ring_status_rejects_typo(db):
    with pytest.raises(RuleValidationError) as exc:
        smart_group_service.validate_rule(
            {"field": "ring.status", "op": "in", "value": ["assigned"]}
        )
    assert "ring.status values must be in" in str(exc.value)


def test_validate_ring_source_kind_accepts_locked_values(db):
    smart_group_service.validate_rule(
        {
            "field": "ring.source_kind",
            "op": "in",
            "value": ["host", "group", "smart_group"],
        }
    )


def test_validate_ring_source_kind_rejects_typo(db):
    with pytest.raises(RuleValidationError) as exc:
        smart_group_service.validate_rule(
            {"field": "ring.source_kind", "op": "in", "value": ["fleet_default"]}
        )
    assert "ring.source_kind values must be in" in str(exc.value)


def test_validate_ring_effective_slug_string_ops(db):
    smart_group_service.validate_rule(
        {"field": "ring.effective_slug", "op": "eq", "value": "canary"}
    )
    smart_group_service.validate_rule(
        {"field": "ring.effective_slug", "op": "contains", "value": "can"}
    )
    smart_group_service.validate_rule(
        {"field": "ring.effective_slug", "op": "regex", "value": "^can"}
    )


def test_validate_ring_has_effective_ring_bool(db):
    smart_group_service.validate_rule(
        {"field": "ring.has_effective_ring", "op": "eq", "value": True}
    )
    with pytest.raises(RuleValidationError):
        smart_group_service.validate_rule(
            {"field": "ring.has_effective_ring", "op": "eq", "value": "yes"}
        )


def test_validate_unknown_ring_field_rejected(db):
    with pytest.raises(RuleValidationError):
        smart_group_service.validate_rule(
            {"field": "ring.bogus", "op": "eq", "value": "x"}
        )


# -- Evaluation against each Slice 2 resolver outcome ----------------------


def test_eval_no_ring_when_unbound(db, admin_user, host):
    # No bindings → status=no_ring, has_effective_ring=False
    assert host.id in smart_group_service.evaluate(
        {"field": "ring.status", "op": "in", "value": ["no_ring"]}, db
    )
    assert host.id in smart_group_service.evaluate(
        {"field": "ring.has_effective_ring", "op": "eq", "value": False}, db
    )


def test_eval_resolved_via_host_binding(db, admin_user, host):
    ring = _make_ring(db, admin_user, "canary-direct", sort_order=1)
    patch_ring_service.bind_host(
        db, ring_id=ring.id, system_id=host.id, actor_user_id=admin_user.id
    )

    # status=resolved, source_kind=host, effective_slug populated
    matches = smart_group_service.evaluate(
        {"field": "ring.status", "op": "in", "value": ["resolved"]}, db
    )
    assert host.id in matches

    matches = smart_group_service.evaluate(
        {"field": "ring.source_kind", "op": "in", "value": ["host"]}, db
    )
    assert host.id in matches

    matches = smart_group_service.evaluate(
        {"field": "ring.effective_slug", "op": "eq", "value": "canary-direct"}, db
    )
    assert host.id in matches

    matches = smart_group_service.evaluate(
        {"field": "ring.has_effective_ring", "op": "eq", "value": True}, db
    )
    assert host.id in matches


def test_eval_resolved_via_static_group(db, admin_user, host, static_group):
    ring = _make_ring(db, admin_user, "via-group", sort_order=1)
    patch_ring_service.bind_group(
        db,
        ring_id=ring.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )

    matches = smart_group_service.evaluate(
        {"field": "ring.source_kind", "op": "in", "value": ["group"]}, db
    )
    assert host.id in matches


def test_eval_resolved_via_smart_group(db, admin_user, host):
    ring = _make_ring(db, admin_user, "via-smart", sort_order=1)
    sg = SmartGroup(
        name="ring-pred-smart-source",
        description="t",
        rule_json="[]",
        enabled=True,
    )
    db.add(sg)
    db.flush()
    db.add(SmartGroupMembership(smart_group_id=sg.id, system_id=host.id))
    db.flush()
    patch_ring_service.bind_smart_group(
        db,
        ring_id=ring.id,
        smart_group_id=sg.id,
        actor_user_id=admin_user.id,
    )

    matches = smart_group_service.evaluate(
        {"field": "ring.source_kind", "op": "in", "value": ["smart_group"]}, db
    )
    assert host.id in matches


def test_eval_conflict_state(db, admin_user, host):
    a = _make_ring(db, admin_user, "conflict-a", sort_order=1)
    b = _make_ring(db, admin_user, "conflict-b", sort_order=2)
    patch_ring_service.bind_host(
        db, ring_id=a.id, system_id=host.id, actor_user_id=admin_user.id
    )
    patch_ring_service.bind_host(
        db, ring_id=b.id, system_id=host.id, actor_user_id=admin_user.id
    )

    matches = smart_group_service.evaluate(
        {"field": "ring.status", "op": "in", "value": ["conflict"]}, db
    )
    assert host.id in matches

    # Conflict hosts must not match the positive policy-specific arms
    # (null-FALSE for source_kind and effective_slug).
    assert host.id not in smart_group_service.evaluate(
        {"field": "ring.source_kind", "op": "in", "value": ["host"]}, db
    )
    assert host.id not in smart_group_service.evaluate(
        {"field": "ring.effective_slug", "op": "eq", "value": "conflict-a"}, db
    )
    assert host.id not in smart_group_service.evaluate(
        {"field": "ring.has_effective_ring", "op": "eq", "value": True}, db
    )


def test_eval_disabled_ring_falls_through(db, admin_user, host, static_group):
    """Disabled rings are filtered by the Slice 2 resolver, so a host
    with only disabled-ring bindings reads as no_ring (not 'resolved
    via a disabled ring')."""
    disabled = _make_ring(db, admin_user, "off", sort_order=1, enabled=False)
    patch_ring_service.bind_host(
        db,
        ring_id=disabled.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )
    matches = smart_group_service.evaluate(
        {"field": "ring.status", "op": "in", "value": ["no_ring"]}, db
    )
    assert host.id in matches


def test_eval_null_false_for_effective_slug_neq_arm(db, admin_user, host):
    """null-FALSE rule: a no_ring host must not match the negative
    arm of a string predicate either. ``neq`` against an unbound host
    should return zero hosts (not all of them)."""
    matches = smart_group_service.evaluate(
        {"field": "ring.effective_slug", "op": "neq", "value": "anything"}, db
    )
    assert host.id not in matches


# -- Cycle guard -----------------------------------------------------------


def test_cycle_guard_blocks_ring_predicate_smart_group_bind(db, admin_user, host):
    sg = _make_smart_group(
        db,
        name="ring-pred-cycle",
        rule={"field": "ring.status", "op": "in", "value": ["resolved"]},
    )
    ring = _make_ring(db, admin_user, "cycle", sort_order=1)
    with pytest.raises(PatchRingError) as exc:
        patch_ring_service.bind_smart_group(
            db,
            ring_id=ring.id,
            smart_group_id=sg.id,
            actor_user_id=admin_user.id,
        )
    assert "cycle" in str(exc.value)


def test_cycle_guard_allows_non_ring_predicate_smart_group_bind(db, admin_user):
    """Sanity: a smart group whose rule does NOT reference ring.*
    should bind cleanly. Confirms the guard isn't over-restrictive."""
    sg = _make_smart_group(
        db,
        name="ring-pred-non-cycle",
        rule={"field": "status", "op": "eq", "value": "Active"},
    )
    ring = _make_ring(db, admin_user, "non-cycle", sort_order=1)
    binding = patch_ring_service.bind_smart_group(
        db,
        ring_id=ring.id,
        smart_group_id=sg.id,
        actor_user_id=admin_user.id,
    )
    assert binding.id is not None


# -- Recompute hooks -------------------------------------------------------


def test_recompute_fires_on_host_binding_change(db, admin_user, host):
    sg = _make_smart_group(
        db,
        name="ring-watch-resolved",
        rule={"field": "ring.status", "op": "in", "value": ["resolved"]},
    )
    smart_group_service.recompute_membership(db, sg.id)
    # Initially the host has no ring bindings, so it should NOT match.
    assert host.id not in smart_group_service.members(db, sg.id)

    ring = _make_ring(db, admin_user, "watch", sort_order=1)
    patch_ring_service.bind_host(
        db, ring_id=ring.id, system_id=host.id, actor_user_id=admin_user.id
    )
    # bind_host fires the recompute hook; cached membership must now
    # reflect the resolver's "resolved" verdict.
    assert host.id in smart_group_service.members(db, sg.id)


def test_recompute_fires_on_ring_name_change(db, admin_user, host):
    """``ring.effective_name`` predicates must
    refresh when a ring is renamed via update_ring.

    Without the fix, the recompute hook only fired on ``enabled``
    changes — ``name`` flowed into the resolver's snapshot but
    dependent smart groups stayed cached against the old name."""
    ring = _make_ring(db, admin_user, "rename-target", sort_order=1)
    patch_ring_service.bind_host(
        db, ring_id=ring.id, system_id=host.id, actor_user_id=admin_user.id
    )

    sg = _make_smart_group(
        db,
        name="ring-watch-name",
        rule={
            "field": "ring.effective_name",
            "op": "eq",
            "value": "rename-target",
        },
    )
    smart_group_service.recompute_membership(db, sg.id)
    # Initial state: name matches the rule, host is a member.
    assert host.id in smart_group_service.members(db, sg.id)

    # Rename the ring. The watcher's rule no longer matches the new
    # name, so the host must drop out of the cached membership without
    # any further binding mutation.
    patch_ring_service.update_ring(
        db,
        ring.id,
        {"name": "renamed-display"},
        actor_user_id=admin_user.id,
    )
    assert host.id not in smart_group_service.members(db, sg.id)

    # And conversely: a watcher tied to the new name picks the host up.
    sg2 = _make_smart_group(
        db,
        name="ring-watch-renamed",
        rule={
            "field": "ring.effective_name",
            "op": "eq",
            "value": "renamed-display",
        },
    )
    smart_group_service.recompute_membership(db, sg2.id)
    assert host.id in smart_group_service.members(db, sg2.id)


def test_recompute_skips_on_irrelevant_field_change(db, admin_user, host, monkeypatch):
    """Sanity: changing fields that no ``ring.*`` predicate exposes
    (description, sort_order) should NOT trigger a recompute. Confirms
    the perf hint is not over-broad."""
    ring = _make_ring(db, admin_user, "irrelevant", sort_order=1)
    patch_ring_service.bind_host(
        db, ring_id=ring.id, system_id=host.id, actor_user_id=admin_user.id
    )

    calls = {"n": 0}
    real_hook = patch_ring_service._recompute_ring_smart_groups

    def counting_hook(db_):
        calls["n"] += 1
        return real_hook(db_)

    monkeypatch.setattr(
        patch_ring_service, "_recompute_ring_smart_groups", counting_hook
    )
    patch_ring_service.update_ring(
        db,
        ring.id,
        {"description": "new desc"},
        actor_user_id=admin_user.id,
    )
    assert calls["n"] == 0

    # Changing sort_order also doesn't affect any ring.* predicate.
    patch_ring_service.update_ring(
        db,
        ring.id,
        {"sort_order": 7},
        actor_user_id=admin_user.id,
    )
    assert calls["n"] == 0

    # But a name change still fires.
    patch_ring_service.update_ring(
        db,
        ring.id,
        {"name": "new-name"},
        actor_user_id=admin_user.id,
    )
    assert calls["n"] == 1


def test_recompute_fires_on_ring_enable_toggle(db, admin_user, host):
    ring = _make_ring(db, admin_user, "toggle", sort_order=1)
    patch_ring_service.bind_host(
        db, ring_id=ring.id, system_id=host.id, actor_user_id=admin_user.id
    )

    sg = _make_smart_group(
        db,
        name="ring-watch-toggle",
        rule={"field": "ring.has_effective_ring", "op": "eq", "value": True},
    )
    smart_group_service.recompute_membership(db, sg.id)
    assert host.id in smart_group_service.members(db, sg.id)

    # Disable the ring via the service path — the resolver now
    # filters it out, so has_effective_ring flips to False.
    patch_ring_service.update_ring(
        db, ring.id, {"enabled": False}, actor_user_id=admin_user.id
    )
    assert host.id not in smart_group_service.members(db, sg.id)


def test_recompute_fires_on_ring_delete(db, admin_user, host):
    ring = _make_ring(db, admin_user, "del", sort_order=1)
    patch_ring_service.bind_host(
        db, ring_id=ring.id, system_id=host.id, actor_user_id=admin_user.id
    )

    sg = _make_smart_group(
        db,
        name="ring-watch-del",
        rule={"field": "ring.has_effective_ring", "op": "eq", "value": True},
    )
    smart_group_service.recompute_membership(db, sg.id)
    assert host.id in smart_group_service.members(db, sg.id)

    patch_ring_service.delete_ring(db, ring.id, actor_user_id=admin_user.id)
    assert host.id not in smart_group_service.members(db, sg.id)


def test_recompute_fires_on_group_binding_change(db, admin_user, host, static_group):
    ring = _make_ring(db, admin_user, "via-group-watch", sort_order=1)
    sg = _make_smart_group(
        db,
        name="ring-watch-group",
        rule={
            "field": "ring.source_kind",
            "op": "in",
            "value": ["group"],
        },
    )
    smart_group_service.recompute_membership(db, sg.id)
    assert host.id not in smart_group_service.members(db, sg.id)

    patch_ring_service.bind_group(
        db,
        ring_id=ring.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )
    assert host.id in smart_group_service.members(db, sg.id)


def test_membership_change_on_ring_binder_refreshes_dependent_ring_groups(
    db, admin_user, host, seed_distro, static_group, credentials
):
    """Cascade hook: when a smart group bound as a ring source has its
    membership change, dependent ``ring.*`` smart groups must refresh
    — even though no ring mutation occurred.

    Mirrors the PRA-161 1e-a ``is_patch_binder`` pattern exactly:
    binder is a real (non-ring) smart group with a hostname rule;
    binder is bound to a ring; when binder's membership changes via
    ``recompute_membership``, the ring-watcher smart group sees the
    new resolver verdict without any direct ring mutation.
    """
    # Binder smart group: real rule, hostname-prefix match. Initially
    # contains only the existing host fixture.
    binder = _make_smart_group(
        db,
        name="ring-binder-hostname",
        rule={
            "field": "hostname",
            "op": "contains",
            "value": "ring-pred-host",
        },
    )
    smart_group_service.recompute_membership(db, binder.id)
    assert host.id in smart_group_service.members(db, binder.id)

    # Bind a ring via the (non-ring-predicate) binder smart group.
    ring = _make_ring(db, admin_user, "binder-ring", sort_order=1)
    patch_ring_service.bind_smart_group(
        db,
        ring_id=ring.id,
        smart_group_id=binder.id,
        actor_user_id=admin_user.id,
    )

    # Watcher: ring.* smart group. Initial membership picks up the host.
    watcher = _make_smart_group(
        db,
        name="ring-watcher",
        rule={"field": "ring.has_effective_ring", "op": "eq", "value": True},
    )
    smart_group_service.recompute_membership(db, watcher.id)
    assert host.id in smart_group_service.members(db, watcher.id)

    # Add a brand-new host that matches the binder's hostname rule.
    new_host = System(
        hostname="ring-pred-host-cascade.example.com",
        ip_address="10.0.0.96",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=static_group.id,
        credentials_id=credentials.id,
    )
    db.add(new_host)
    db.commit()
    db.refresh(new_host)

    # Re-evaluate the binder. The new host joins binder, which means
    # the ring resolver now resolves to the bound ring via smart_group
    # tier for the new host. The cascade hook on recompute_membership
    # must refresh ring.* watchers — without it, new_host would stay
    # missing from watcher until the next sweep.
    smart_group_service.recompute_membership(db, binder.id)

    assert new_host.id in smart_group_service.members(db, watcher.id)
