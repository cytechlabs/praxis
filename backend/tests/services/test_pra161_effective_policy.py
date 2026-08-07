"""PRA-161 slice 1d — effective-policy resolver service tests.

Covers:
* Precedence: direct host > static group > smart group > fleet default.
* Disabled-policy skipping at every tier (including fleet default).
* Same-tier conflicts surface as ``EffectivePolicyConflict`` with
  tier + policy ids.
* Missing host raises a regular ``PatchPolicyError`` (route maps to 404).
* No-policy result is the explicit ``("no_policy")`` tuple, not an exception.
* Fleet-default set/clear preserves the partial-unique invariant
  atomically and emits ``patch_policy.fleet_default_set`` /
  ``patch_policy.fleet_default_cleared`` audit events without ``db=``.
"""

from __future__ import annotations

import pytest

from app.db.models import (
    Credential,
    Group,
    PatchPolicy,
    SmartGroup,
    SmartGroupMembership,
    System,
)
from app.services import patch_policy_service
from app.services.patch_policy_service import (
    AUDIT_PATCH_POLICY_FLEET_DEFAULT_CLEARED,
    AUDIT_PATCH_POLICY_FLEET_DEFAULT_SET,
    RESOLUTION_DIRECT_HOST,
    RESOLUTION_FLEET_DEFAULT,
    RESOLUTION_NO_POLICY,
    RESOLUTION_SMART_GROUP,
    RESOLUTION_STATIC_GROUP,
    EffectivePolicyConflict,
    PatchPolicyError,
)

# -- Fixtures ---------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="effective-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="effective-test-cred",
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
        hostname="effective-test-host.example.com",
        ip_address="10.0.0.30",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=static_group.id,
        credentials_id=credentials.id,
    )
    db.add(s)
    db.flush()
    return s


@pytest.fixture
def smart_group_with_host(db, host) -> SmartGroup:
    sg = SmartGroup(
        name="effective-test-smart",
        description="t",
        rule_json="[]",
        enabled=True,
    )
    db.add(sg)
    db.flush()
    db.add(SmartGroupMembership(smart_group_id=sg.id, system_id=host.id))
    db.flush()
    return sg


def _make_policy(db, admin_user, slug, *, enabled=True, fleet_default=False):
    p = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind="security_only",
        enabled=enabled,
    )
    if fleet_default:
        p.is_fleet_default = True
        db.commit()
        db.refresh(p)
    return p


# -- Precedence -------------------------------------------------------------


def test_resolve_direct_host_wins_over_group(
    db, admin_user, host, static_group, smart_group_with_host
):
    direct = _make_policy(db, admin_user, "direct")
    group_pol = _make_policy(db, admin_user, "group")
    smart_pol = _make_policy(db, admin_user, "smart")
    fleet_pol = _make_policy(db, admin_user, "fleet", fleet_default=True)

    patch_policy_service.bind_host(
        db,
        policy_id=direct.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )
    patch_policy_service.bind_group(
        db,
        policy_id=group_pol.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )
    patch_policy_service.bind_smart_group(
        db,
        policy_id=smart_pol.id,
        smart_group_id=smart_group_with_host.id,
        actor_user_id=admin_user.id,
    )

    policy, kind = patch_policy_service.resolve_effective_policy(db, host.id)
    assert kind == RESOLUTION_DIRECT_HOST
    assert policy is not None and policy.id == direct.id


def test_resolve_static_group_wins_over_smart_group_and_fleet(
    db, admin_user, host, static_group, smart_group_with_host
):
    group_pol = _make_policy(db, admin_user, "group")
    smart_pol = _make_policy(db, admin_user, "smart")
    _make_policy(db, admin_user, "fleet", fleet_default=True)

    patch_policy_service.bind_group(
        db,
        policy_id=group_pol.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )
    patch_policy_service.bind_smart_group(
        db,
        policy_id=smart_pol.id,
        smart_group_id=smart_group_with_host.id,
        actor_user_id=admin_user.id,
    )

    policy, kind = patch_policy_service.resolve_effective_policy(db, host.id)
    assert kind == RESOLUTION_STATIC_GROUP
    assert policy.id == group_pol.id


def test_resolve_smart_group_wins_over_fleet(
    db, admin_user, host, smart_group_with_host
):
    smart_pol = _make_policy(db, admin_user, "smart")
    _make_policy(db, admin_user, "fleet", fleet_default=True)

    patch_policy_service.bind_smart_group(
        db,
        policy_id=smart_pol.id,
        smart_group_id=smart_group_with_host.id,
        actor_user_id=admin_user.id,
    )

    policy, kind = patch_policy_service.resolve_effective_policy(db, host.id)
    assert kind == RESOLUTION_SMART_GROUP
    assert policy.id == smart_pol.id


def test_resolve_falls_through_to_fleet_default(db, admin_user, host):
    fleet_pol = _make_policy(db, admin_user, "fleet", fleet_default=True)

    policy, kind = patch_policy_service.resolve_effective_policy(db, host.id)
    assert kind == RESOLUTION_FLEET_DEFAULT
    assert policy.id == fleet_pol.id


def test_resolve_returns_no_policy_when_no_match(db, host):
    policy, kind = patch_policy_service.resolve_effective_policy(db, host.id)
    assert policy is None
    assert kind == RESOLUTION_NO_POLICY


# -- Disabled-skip ----------------------------------------------------------


def test_disabled_direct_policy_falls_through(db, admin_user, host, static_group):
    disabled_direct = _make_policy(db, admin_user, "disabled-direct", enabled=False)
    enabled_group = _make_policy(db, admin_user, "enabled-group")
    patch_policy_service.bind_host(
        db,
        policy_id=disabled_direct.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )
    patch_policy_service.bind_group(
        db,
        policy_id=enabled_group.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )

    policy, kind = patch_policy_service.resolve_effective_policy(db, host.id)
    assert kind == RESOLUTION_STATIC_GROUP
    assert policy.id == enabled_group.id


def test_disabled_fleet_default_yields_no_policy(db, admin_user, host):
    _make_policy(db, admin_user, "disabled-fleet", enabled=False, fleet_default=True)
    policy, kind = patch_policy_service.resolve_effective_policy(db, host.id)
    assert policy is None
    assert kind == RESOLUTION_NO_POLICY


def test_disabled_smart_group_falls_through(db, admin_user, host):
    """Slice 1d-a regression: a smart group with
    ``enabled = False`` must be ignored at the smart-group resolver
    tier. ``SmartGroupMembership`` rows are a materialized cache that
    can outlive an enable-toggle, so the resolver must filter on
    ``SmartGroup.enabled`` directly. Otherwise a disabled smart group
    can still make a policy effective — operator expectation is that
    disabling a smart group removes it from policy targeting.
    """
    sg = SmartGroup(
        name="disabled-smart",
        description="t",
        rule_json="[]",
        enabled=False,  # the lock under test
    )
    db.add(sg)
    db.flush()
    db.add(SmartGroupMembership(smart_group_id=sg.id, system_id=host.id))
    db.flush()

    smart_pol = _make_policy(db, admin_user, "smart-via-disabled-sg")
    patch_policy_service.bind_smart_group(
        db,
        policy_id=smart_pol.id,
        smart_group_id=sg.id,
        actor_user_id=admin_user.id,
    )

    # Without a fleet default we should fall all the way through to no_policy.
    policy, kind = patch_policy_service.resolve_effective_policy(db, host.id)
    assert policy is None
    assert kind == RESOLUTION_NO_POLICY

    # With a fleet default configured, the smart-group tier still
    # gets skipped and the resolver falls through to fleet_default.
    fleet = _make_policy(db, admin_user, "fleet-after-skip", fleet_default=True)
    policy, kind = patch_policy_service.resolve_effective_policy(db, host.id)
    assert kind == RESOLUTION_FLEET_DEFAULT
    assert policy.id == fleet.id


def test_disabled_smart_group_does_not_cause_conflict(db, admin_user, host):
    """A disabled smart group should not even count toward same-tier
    conflict detection. If it did, an operator could not 'soft-park' a
    smart-group binding by toggling the smart group itself off."""
    enabled_sg = SmartGroup(
        name="enabled-after-disabled",
        description="t",
        rule_json="[]",
        enabled=True,
    )
    disabled_sg = SmartGroup(
        name="disabled-conflict",
        description="t",
        rule_json="[]",
        enabled=False,
    )
    db.add_all([enabled_sg, disabled_sg])
    db.flush()
    db.add_all(
        [
            SmartGroupMembership(smart_group_id=enabled_sg.id, system_id=host.id),
            SmartGroupMembership(smart_group_id=disabled_sg.id, system_id=host.id),
        ]
    )
    db.flush()

    p_enabled = _make_policy(db, admin_user, "via-enabled-sg")
    p_disabled = _make_policy(db, admin_user, "via-disabled-sg")
    patch_policy_service.bind_smart_group(
        db,
        policy_id=p_enabled.id,
        smart_group_id=enabled_sg.id,
        actor_user_id=admin_user.id,
    )
    patch_policy_service.bind_smart_group(
        db,
        policy_id=p_disabled.id,
        smart_group_id=disabled_sg.id,
        actor_user_id=admin_user.id,
    )

    policy, kind = patch_policy_service.resolve_effective_policy(db, host.id)
    assert kind == RESOLUTION_SMART_GROUP
    assert policy.id == p_enabled.id


# -- Conflicts --------------------------------------------------------------


def test_two_direct_bindings_raise_conflict(db, admin_user, host):
    p1 = _make_policy(db, admin_user, "p1")
    p2 = _make_policy(db, admin_user, "p2")
    patch_policy_service.bind_host(
        db, policy_id=p1.id, system_id=host.id, actor_user_id=admin_user.id
    )
    patch_policy_service.bind_host(
        db, policy_id=p2.id, system_id=host.id, actor_user_id=admin_user.id
    )

    with pytest.raises(EffectivePolicyConflict) as ei:
        patch_policy_service.resolve_effective_policy(db, host.id)
    assert ei.value.tier == RESOLUTION_DIRECT_HOST
    slugs = {slug for _, slug in ei.value.policies}
    assert slugs == {"p1", "p2"}


def test_two_static_group_bindings_raise_conflict(db, admin_user, host, static_group):
    p1 = _make_policy(db, admin_user, "g1")
    p2 = _make_policy(db, admin_user, "g2")
    patch_policy_service.bind_group(
        db,
        policy_id=p1.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )
    patch_policy_service.bind_group(
        db,
        policy_id=p2.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )

    with pytest.raises(EffectivePolicyConflict) as ei:
        patch_policy_service.resolve_effective_policy(db, host.id)
    assert ei.value.tier == RESOLUTION_STATIC_GROUP


def test_two_smart_groups_with_same_host_raise_conflict(db, admin_user, host):
    sg1 = SmartGroup(name="sg1", description="t", rule_json="[]", enabled=True)
    sg2 = SmartGroup(name="sg2", description="t", rule_json="[]", enabled=True)
    db.add_all([sg1, sg2])
    db.flush()
    db.add(SmartGroupMembership(smart_group_id=sg1.id, system_id=host.id))
    db.add(SmartGroupMembership(smart_group_id=sg2.id, system_id=host.id))
    db.flush()

    p1 = _make_policy(db, admin_user, "s1")
    p2 = _make_policy(db, admin_user, "s2")
    patch_policy_service.bind_smart_group(
        db,
        policy_id=p1.id,
        smart_group_id=sg1.id,
        actor_user_id=admin_user.id,
    )
    patch_policy_service.bind_smart_group(
        db,
        policy_id=p2.id,
        smart_group_id=sg2.id,
        actor_user_id=admin_user.id,
    )

    with pytest.raises(EffectivePolicyConflict) as ei:
        patch_policy_service.resolve_effective_policy(db, host.id)
    assert ei.value.tier == RESOLUTION_SMART_GROUP


# -- Missing host -----------------------------------------------------------


def test_missing_host_raises_patch_policy_error(db):
    with pytest.raises(PatchPolicyError) as ei:
        patch_policy_service.resolve_effective_policy(db, 999_999)
    assert "host id=999999 not found" in str(ei.value)
    # Not an EffectivePolicyConflict — generic missing-host signal.
    assert not isinstance(ei.value, EffectivePolicyConflict)


# -- set_fleet_default / clear_fleet_default --------------------------------


def test_set_fleet_default_atomically_clears_prior(db, admin_user):
    old = _make_policy(db, admin_user, "old-fleet", fleet_default=True)
    new = _make_policy(db, admin_user, "new-fleet")

    out = patch_policy_service.set_fleet_default(
        db, new.id, actor_user_id=admin_user.id
    )
    assert out.is_fleet_default is True

    db.refresh(old)
    assert old.is_fleet_default is False

    # Partial-unique invariant: only one row has is_fleet_default=true.
    fleet_count = (
        db.query(PatchPolicy).filter(PatchPolicy.is_fleet_default.is_(True)).count()
    )
    assert fleet_count == 1


def test_set_fleet_default_idempotent(db, admin_user, monkeypatch):
    p = _make_policy(db, admin_user, "fleet-idempotent", fleet_default=True)

    captured = []
    monkeypatch.setattr(
        patch_policy_service,
        "safe_emit",
        lambda **kw: captured.append(kw),
    )
    out = patch_policy_service.set_fleet_default(db, p.id, actor_user_id=admin_user.id)
    assert out.id == p.id
    assert out.is_fleet_default is True
    assert captured == []  # no audit emit on no-op


def test_set_fleet_default_emits_audit(db, admin_user, monkeypatch):
    p = _make_policy(db, admin_user, "fleet-audit")
    captured = {}
    monkeypatch.setattr(
        patch_policy_service,
        "safe_emit",
        lambda **kw: captured.update(kw),
    )

    patch_policy_service.set_fleet_default(
        db,
        p.id,
        actor_user_id=admin_user.id,
        actor_username="admin",
        actor_ip="10.0.0.1",
    )
    assert captured["action"] == AUDIT_PATCH_POLICY_FLEET_DEFAULT_SET
    assert captured["target_kind"] == "patch_policy"
    assert captured["target_id"] == str(p.id)
    assert captured["context"]["policy_slug"] == p.slug
    assert "db" not in captured


def test_set_fleet_default_records_previous_in_audit(db, admin_user, monkeypatch):
    old = _make_policy(db, admin_user, "old", fleet_default=True)
    new = _make_policy(db, admin_user, "new")
    captured = {}
    monkeypatch.setattr(
        patch_policy_service,
        "safe_emit",
        lambda **kw: captured.update(kw),
    )
    patch_policy_service.set_fleet_default(db, new.id, actor_user_id=admin_user.id)
    assert captured["context"]["previous_fleet_default_id"] == old.id
    assert captured["context"]["previous_fleet_default_slug"] == old.slug


def test_clear_fleet_default_removes_flag(db, admin_user):
    p = _make_policy(db, admin_user, "to-clear", fleet_default=True)
    out = patch_policy_service.clear_fleet_default(
        db, p.id, actor_user_id=admin_user.id
    )
    assert out.is_fleet_default is False


def test_clear_fleet_default_idempotent(db, admin_user, monkeypatch):
    p = _make_policy(db, admin_user, "never-fleet")
    captured = []
    monkeypatch.setattr(
        patch_policy_service,
        "safe_emit",
        lambda **kw: captured.append(kw),
    )
    patch_policy_service.clear_fleet_default(db, p.id, actor_user_id=admin_user.id)
    assert captured == []


def test_clear_fleet_default_emits_audit(db, admin_user, monkeypatch):
    p = _make_policy(db, admin_user, "clear-audit", fleet_default=True)
    captured = {}
    monkeypatch.setattr(
        patch_policy_service,
        "safe_emit",
        lambda **kw: captured.update(kw),
    )
    patch_policy_service.clear_fleet_default(db, p.id, actor_user_id=admin_user.id)
    assert captured["action"] == AUDIT_PATCH_POLICY_FLEET_DEFAULT_CLEARED
    assert "db" not in captured


def test_set_fleet_default_unknown_policy_raises(db, admin_user):
    with pytest.raises(PatchPolicyError) as ei:
        patch_policy_service.set_fleet_default(db, 999_999, actor_user_id=admin_user.id)
    assert "not found" in str(ei.value)


# -- DB partial-unique safety net ------------------------------------------


def test_db_partial_unique_blocks_two_fleet_defaults(db, admin_user):
    """Service path keeps the invariant clean; the DB partial unique
    is the safety net for direct ORM bypasses."""
    p1 = _make_policy(db, admin_user, "fd1", fleet_default=True)
    p2 = PatchPolicy(
        slug="fd2",
        name="fd2",
        scope_kind="security_only",
        scope_packages=[],
        reboot_policy="never",
        rollout_cadence="immediate",
        failure_policy="continue",
        created_by=admin_user.id,
        is_fleet_default=True,
    )
    db.add(p2)
    with pytest.raises(Exception):
        db.flush()
    db.rollback()
