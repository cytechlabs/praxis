"""PRA-162 slice 2 — effective-ring resolver service tests.

Covers:
* Precedence: direct host > static group > smart group.
* Same-tier distinct-ring conflict surfaces as ``status="conflict"``
  with candidates and a ``source_tier``.
* Same-tier duplicate paths to the *same* ring resolve cleanly.
* Disabled-ring filtering at every tier.
* Disabled-smart-group filtering at the smart-group tier (the
  ``SmartGroupMembership`` cache can outlive an enable-toggle, same as
  the patch-policy resolver's filter).
* No tier matches → ``status="no_ring"``.
* Missing host raises a regular ``PatchRingError`` (route maps to 404).
* Resolver does not emit audit rows (read-only).
"""

from __future__ import annotations

import pytest

from app.db.models import Credential, Group, SmartGroup, SmartGroupMembership, System
from app.services import patch_ring_service
from app.services.patch_ring_service import (
    SOURCE_TIER_GROUP,
    SOURCE_TIER_HOST,
    SOURCE_TIER_SMART_GROUP,
    STATUS_CONFLICT,
    STATUS_NO_RING,
    STATUS_RESOLVED,
    PatchRingError,
)

# -- Fixtures ---------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="effective-ring-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="effective-ring-test-cred",
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
        hostname="effective-ring-test-host.example.com",
        ip_address="10.0.0.80",
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
        name="effective-ring-test-smart",
        description="t",
        rule_json="[]",
        enabled=True,
    )
    db.add(sg)
    db.flush()
    db.add(SmartGroupMembership(smart_group_id=sg.id, system_id=host.id))
    db.flush()
    return sg


def _make_ring(db, admin_user, slug, *, sort_order, enabled=True):
    return patch_ring_service.create_ring(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        sort_order=sort_order,
        enabled=enabled,
    )


# -- Precedence -------------------------------------------------------------


def test_resolve_direct_host_wins_over_group_and_smart(
    db, admin_user, host, static_group, smart_group_with_host
):
    direct = _make_ring(db, admin_user, "host-direct", sort_order=1)
    group_ring = _make_ring(db, admin_user, "group-ring", sort_order=2)
    smart_ring = _make_ring(db, admin_user, "smart-ring", sort_order=3)

    patch_ring_service.bind_host(
        db, ring_id=direct.id, system_id=host.id, actor_user_id=admin_user.id
    )
    patch_ring_service.bind_group(
        db,
        ring_id=group_ring.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )
    patch_ring_service.bind_smart_group(
        db,
        ring_id=smart_ring.id,
        smart_group_id=smart_group_with_host.id,
        actor_user_id=admin_user.id,
    )

    result = patch_ring_service.resolve_effective_ring(db, host.id)
    assert result.status == STATUS_RESOLVED
    assert result.source_tier == SOURCE_TIER_HOST
    assert result.ring is not None and result.ring.id == direct.id
    assert result.candidates == []


def test_resolve_static_group_wins_over_smart_group(
    db, admin_user, host, static_group, smart_group_with_host
):
    group_ring = _make_ring(db, admin_user, "group-ring", sort_order=1)
    smart_ring = _make_ring(db, admin_user, "smart-ring", sort_order=2)

    patch_ring_service.bind_group(
        db,
        ring_id=group_ring.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )
    patch_ring_service.bind_smart_group(
        db,
        ring_id=smart_ring.id,
        smart_group_id=smart_group_with_host.id,
        actor_user_id=admin_user.id,
    )

    result = patch_ring_service.resolve_effective_ring(db, host.id)
    assert result.status == STATUS_RESOLVED
    assert result.source_tier == SOURCE_TIER_GROUP
    assert result.ring.id == group_ring.id


def test_resolve_smart_group_when_no_higher_tier(
    db, admin_user, host, smart_group_with_host
):
    smart_ring = _make_ring(db, admin_user, "smart-only", sort_order=1)
    patch_ring_service.bind_smart_group(
        db,
        ring_id=smart_ring.id,
        smart_group_id=smart_group_with_host.id,
        actor_user_id=admin_user.id,
    )

    result = patch_ring_service.resolve_effective_ring(db, host.id)
    assert result.status == STATUS_RESOLVED
    assert result.source_tier == SOURCE_TIER_SMART_GROUP
    assert result.ring.id == smart_ring.id


def test_resolve_no_ring_when_no_bindings(db, host):
    result = patch_ring_service.resolve_effective_ring(db, host.id)
    assert result.status == STATUS_NO_RING
    assert result.source_tier is None
    assert result.ring is None
    assert result.candidates == []
    assert result.message  # explanatory string for operators


# -- Conflict ---------------------------------------------------------------


def test_same_tier_distinct_rings_at_host_tier_conflict(db, admin_user, host):
    a = _make_ring(db, admin_user, "ring-a", sort_order=1)
    b = _make_ring(db, admin_user, "ring-b", sort_order=2)
    patch_ring_service.bind_host(
        db, ring_id=a.id, system_id=host.id, actor_user_id=admin_user.id
    )
    patch_ring_service.bind_host(
        db, ring_id=b.id, system_id=host.id, actor_user_id=admin_user.id
    )

    result = patch_ring_service.resolve_effective_ring(db, host.id)
    assert result.status == STATUS_CONFLICT
    assert result.source_tier == SOURCE_TIER_HOST
    assert result.ring is None
    assert sorted(c.slug for c in result.candidates) == ["ring-a", "ring-b"]
    assert "ring-a" in (result.message or "")


def test_same_tier_distinct_rings_at_group_tier_conflict(
    db, admin_user, host, static_group
):
    a = _make_ring(db, admin_user, "g-a", sort_order=1)
    b = _make_ring(db, admin_user, "g-b", sort_order=2)
    patch_ring_service.bind_group(
        db, ring_id=a.id, group_id=static_group.id, actor_user_id=admin_user.id
    )
    patch_ring_service.bind_group(
        db, ring_id=b.id, group_id=static_group.id, actor_user_id=admin_user.id
    )

    result = patch_ring_service.resolve_effective_ring(db, host.id)
    assert result.status == STATUS_CONFLICT
    assert result.source_tier == SOURCE_TIER_GROUP
    assert sorted(c.slug for c in result.candidates) == ["g-a", "g-b"]


def test_same_tier_distinct_rings_at_smart_tier_conflict(
    db, admin_user, host, smart_group_with_host
):
    # Two distinct rings bound to the same enabled smart group
    a = _make_ring(db, admin_user, "s-a", sort_order=1)
    b = _make_ring(db, admin_user, "s-b", sort_order=2)
    patch_ring_service.bind_smart_group(
        db,
        ring_id=a.id,
        smart_group_id=smart_group_with_host.id,
        actor_user_id=admin_user.id,
    )
    patch_ring_service.bind_smart_group(
        db,
        ring_id=b.id,
        smart_group_id=smart_group_with_host.id,
        actor_user_id=admin_user.id,
    )

    result = patch_ring_service.resolve_effective_ring(db, host.id)
    assert result.status == STATUS_CONFLICT
    assert result.source_tier == SOURCE_TIER_SMART_GROUP


def test_same_ring_via_two_smart_groups_does_not_conflict(
    db, admin_user, host, smart_group_with_host
):
    """Multiple paths to the *same* ring within a tier resolve cleanly,
    not as conflict — the resolver dedupes on ring identity."""
    sg2 = SmartGroup(
        name="effective-ring-test-smart-2",
        description="t",
        rule_json="[]",
        enabled=True,
    )
    db.add(sg2)
    db.flush()
    db.add(SmartGroupMembership(smart_group_id=sg2.id, system_id=host.id))
    db.flush()

    ring = _make_ring(db, admin_user, "shared", sort_order=1)
    patch_ring_service.bind_smart_group(
        db,
        ring_id=ring.id,
        smart_group_id=smart_group_with_host.id,
        actor_user_id=admin_user.id,
    )
    patch_ring_service.bind_smart_group(
        db,
        ring_id=ring.id,
        smart_group_id=sg2.id,
        actor_user_id=admin_user.id,
    )

    result = patch_ring_service.resolve_effective_ring(db, host.id)
    assert result.status == STATUS_RESOLVED
    assert result.source_tier == SOURCE_TIER_SMART_GROUP
    assert result.ring.id == ring.id


def test_conflict_higher_tier_short_circuits_lower_tiers(
    db, admin_user, host, static_group, smart_group_with_host
):
    """Conflict at the host tier must NOT silently fall through to
    the group tier — the resolver returns the conflict at the
    highest-precedence tier where it occurs."""
    a = _make_ring(db, admin_user, "host-a", sort_order=1)
    b = _make_ring(db, admin_user, "host-b", sort_order=2)
    group_ring = _make_ring(db, admin_user, "group-pick", sort_order=3)

    patch_ring_service.bind_host(
        db, ring_id=a.id, system_id=host.id, actor_user_id=admin_user.id
    )
    patch_ring_service.bind_host(
        db, ring_id=b.id, system_id=host.id, actor_user_id=admin_user.id
    )
    patch_ring_service.bind_group(
        db,
        ring_id=group_ring.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )

    result = patch_ring_service.resolve_effective_ring(db, host.id)
    assert result.status == STATUS_CONFLICT
    assert result.source_tier == SOURCE_TIER_HOST


# -- Disabled-ring filtering -----------------------------------------------


def test_disabled_ring_at_host_tier_falls_through(db, admin_user, host, static_group):
    disabled = _make_ring(db, admin_user, "host-disabled", sort_order=1, enabled=False)
    group_ring = _make_ring(db, admin_user, "group-fallback", sort_order=2)

    patch_ring_service.bind_host(
        db, ring_id=disabled.id, system_id=host.id, actor_user_id=admin_user.id
    )
    patch_ring_service.bind_group(
        db,
        ring_id=group_ring.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )

    result = patch_ring_service.resolve_effective_ring(db, host.id)
    assert result.status == STATUS_RESOLVED
    assert result.source_tier == SOURCE_TIER_GROUP
    assert result.ring.id == group_ring.id


def test_disabled_ring_does_not_create_conflict(db, admin_user, host):
    enabled = _make_ring(db, admin_user, "enabled", sort_order=1)
    disabled = _make_ring(db, admin_user, "disabled", sort_order=2, enabled=False)
    patch_ring_service.bind_host(
        db, ring_id=enabled.id, system_id=host.id, actor_user_id=admin_user.id
    )
    patch_ring_service.bind_host(
        db, ring_id=disabled.id, system_id=host.id, actor_user_id=admin_user.id
    )

    result = patch_ring_service.resolve_effective_ring(db, host.id)
    assert result.status == STATUS_RESOLVED
    assert result.ring.id == enabled.id


def test_all_disabled_rings_resolve_no_ring(db, admin_user, host):
    a = _make_ring(db, admin_user, "off-a", sort_order=1, enabled=False)
    b = _make_ring(db, admin_user, "off-b", sort_order=2, enabled=False)
    patch_ring_service.bind_host(
        db, ring_id=a.id, system_id=host.id, actor_user_id=admin_user.id
    )
    patch_ring_service.bind_host(
        db, ring_id=b.id, system_id=host.id, actor_user_id=admin_user.id
    )

    result = patch_ring_service.resolve_effective_ring(db, host.id)
    assert result.status == STATUS_NO_RING


# -- Disabled-smart-group filtering ----------------------------------------


def test_disabled_smart_group_falls_through(
    db, admin_user, host, smart_group_with_host
):
    """Cache-laundering protection: a smart group toggled off after
    membership was materialized must not still produce a ring."""
    smart_ring = _make_ring(db, admin_user, "smart-laundry", sort_order=1)
    patch_ring_service.bind_smart_group(
        db,
        ring_id=smart_ring.id,
        smart_group_id=smart_group_with_host.id,
        actor_user_id=admin_user.id,
    )
    smart_group_with_host.enabled = False
    db.commit()

    result = patch_ring_service.resolve_effective_ring(db, host.id)
    assert result.status == STATUS_NO_RING


def test_disabled_smart_group_does_not_cause_conflict(
    db, admin_user, host, smart_group_with_host
):
    other = SmartGroup(
        name="effective-ring-test-smart-other",
        description="t",
        rule_json="[]",
        enabled=True,
    )
    db.add(other)
    db.flush()
    db.add(SmartGroupMembership(smart_group_id=other.id, system_id=host.id))
    db.flush()

    a = _make_ring(db, admin_user, "via-disabled", sort_order=1)
    b = _make_ring(db, admin_user, "via-enabled", sort_order=2)
    patch_ring_service.bind_smart_group(
        db,
        ring_id=a.id,
        smart_group_id=smart_group_with_host.id,
        actor_user_id=admin_user.id,
    )
    patch_ring_service.bind_smart_group(
        db,
        ring_id=b.id,
        smart_group_id=other.id,
        actor_user_id=admin_user.id,
    )
    smart_group_with_host.enabled = False
    db.commit()

    result = patch_ring_service.resolve_effective_ring(db, host.id)
    assert result.status == STATUS_RESOLVED
    assert result.ring.id == b.id


# -- Errors / read-only -----------------------------------------------------


def test_resolve_unknown_host_raises_patch_ring_error(db):
    with pytest.raises(PatchRingError) as exc:
        patch_ring_service.resolve_effective_ring(db, 999_999)
    assert "not found" in str(exc.value)


def test_resolver_does_not_emit_audit(db, admin_user, host, monkeypatch):
    """Pure read resolver — no audit row, no commit, no side effects."""
    captured = []

    def fake_safe_emit(**kwargs):
        captured.append(kwargs)

    monkeypatch.setattr(patch_ring_service, "safe_emit", fake_safe_emit)

    ring = _make_ring(db, admin_user, "audit-check", sort_order=1)
    patch_ring_service.bind_host(
        db, ring_id=ring.id, system_id=host.id, actor_user_id=admin_user.id
    )
    captured.clear()  # ignore audit from setup mutations

    patch_ring_service.resolve_effective_ring(db, host.id)
    patch_ring_service.resolve_effective_ring(db, host.id)
    assert captured == []
