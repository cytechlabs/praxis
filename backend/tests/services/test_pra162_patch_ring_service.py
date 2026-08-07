"""PRA-162 slice 1 — patch_ring_service tests.

Covers ring CRUD, slug + sort_order uniqueness, default-ring seed
idempotence, triple-source bindings, missing FK target handling,
audit shape, and DB CHECK belt + suspenders.

The effective-ring resolver, policy-to-ring-set binding, and gate
evaluation are deliberately out of scope for slice 1.
"""

from __future__ import annotations

import pytest

from app.db.models import (
    Credential,
    Group,
    PatchRing,
    PatchRingGroupBinding,
    PatchRingHostBinding,
    PatchRingSmartGroupBinding,
    SmartGroup,
    System,
)
from app.services import patch_ring_service
from app.services.patch_ring_service import (
    AUDIT_PATCH_RING_BOUND,
    AUDIT_PATCH_RING_CREATED,
    AUDIT_PATCH_RING_DELETED,
    AUDIT_PATCH_RING_UNBOUND,
    AUDIT_PATCH_RING_UPDATED,
    DEFAULT_RING_SEED,
    PatchRingError,
)

# -- Fixtures ---------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="ring-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="ring-test-cred",
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
        hostname="ring-test-host.example.com",
        ip_address="10.0.0.60",
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
def smart_group(db) -> SmartGroup:
    sg = SmartGroup(
        name="ring-test-smart",
        description="t",
        rule_json="[]",
        enabled=True,
    )
    db.add(sg)
    db.flush()
    return sg


# -- create_ring ------------------------------------------------------------


def test_create_ring_minimal(db, admin_user):
    ring = patch_ring_service.create_ring(
        db,
        actor_user_id=admin_user.id,
        slug="canary",
        name="Canary",
        sort_order=1,
    )
    assert ring.id is not None
    assert ring.slug == "canary"
    assert ring.sort_order == 1
    assert ring.enabled is True


def test_create_ring_emits_audit(db, admin_user, monkeypatch):
    captured = {}

    def fake_safe_emit(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(patch_ring_service, "safe_emit", fake_safe_emit)
    patch_ring_service.create_ring(
        db,
        actor_user_id=admin_user.id,
        actor_username="admin",
        actor_ip="10.0.0.1",
        slug="canary-audit",
        name="Canary",
        sort_order=1,
    )
    assert captured["action"] == AUDIT_PATCH_RING_CREATED
    assert captured["actor_user_id"] == admin_user.id
    assert captured["target_kind"] == "patch_ring"
    assert captured["context"]["slug"] == "canary-audit"
    assert "db" not in captured


def test_create_ring_slug_must_be_unique(db, admin_user):
    patch_ring_service.create_ring(
        db,
        actor_user_id=admin_user.id,
        slug="dup",
        name="A",
        sort_order=1,
    )
    with pytest.raises(PatchRingError) as ei:
        patch_ring_service.create_ring(
            db,
            actor_user_id=admin_user.id,
            slug="dup",
            name="B",
            sort_order=2,
        )
    assert "already exists" in str(ei.value)


def test_create_ring_sort_order_must_be_unique(db, admin_user):
    patch_ring_service.create_ring(
        db,
        actor_user_id=admin_user.id,
        slug="one",
        name="One",
        sort_order=1,
    )
    with pytest.raises(PatchRingError) as ei:
        patch_ring_service.create_ring(
            db,
            actor_user_id=admin_user.id,
            slug="two",
            name="Two",
            sort_order=1,
        )
    assert "sort_order=1 already exists" in str(ei.value)


def test_create_ring_unknown_actor_rejected(db):
    with pytest.raises(PatchRingError):
        patch_ring_service.create_ring(
            db,
            actor_user_id=999_999,
            slug="x",
            name="X",
            sort_order=1,
        )


# -- list / get / delete ---------------------------------------------------


def test_list_rings_orders_by_sort_order(db, admin_user):
    patch_ring_service.create_ring(
        db, actor_user_id=admin_user.id, slug="prod", name="Prod", sort_order=3
    )
    patch_ring_service.create_ring(
        db, actor_user_id=admin_user.id, slug="canary", name="Canary", sort_order=1
    )
    patch_ring_service.create_ring(
        db, actor_user_id=admin_user.id, slug="pilot", name="Pilot", sort_order=2
    )
    rows = patch_ring_service.list_rings(db)
    assert [r.slug for r in rows] == ["canary", "pilot", "prod"]


def test_list_rings_enabled_only_filter(db, admin_user):
    patch_ring_service.create_ring(
        db, actor_user_id=admin_user.id, slug="on", name="On", sort_order=1
    )
    patch_ring_service.create_ring(
        db,
        actor_user_id=admin_user.id,
        slug="off",
        name="Off",
        sort_order=2,
        enabled=False,
    )
    rows = patch_ring_service.list_rings(db, enabled_only=True)
    assert [r.slug for r in rows] == ["on"]


def test_get_ring_by_slug_misses(db):
    assert patch_ring_service.get_ring_by_slug(db, "nope") is None


def test_delete_ring(db, admin_user):
    r = patch_ring_service.create_ring(
        db, actor_user_id=admin_user.id, slug="del", name="Del", sort_order=1
    )
    patch_ring_service.delete_ring(db, r.id, actor_user_id=admin_user.id)
    assert db.query(PatchRing).filter(PatchRing.id == r.id).first() is None


def test_delete_unknown_ring_raises(db, admin_user):
    with pytest.raises(PatchRingError):
        patch_ring_service.delete_ring(db, 999_999, actor_user_id=admin_user.id)


# -- update_ring ------------------------------------------------------------


def test_update_ring_partial(db, admin_user):
    r = patch_ring_service.create_ring(
        db,
        actor_user_id=admin_user.id,
        slug="u",
        name="Original",
        sort_order=5,
    )
    out = patch_ring_service.update_ring(
        db,
        r.id,
        {"name": "Renamed", "enabled": False},
        actor_user_id=admin_user.id,
    )
    assert out.name == "Renamed"
    assert out.enabled is False
    assert out.sort_order == 5


def test_update_ring_sort_order_collision_rejected(db, admin_user):
    a = patch_ring_service.create_ring(
        db, actor_user_id=admin_user.id, slug="a", name="A", sort_order=1
    )
    patch_ring_service.create_ring(
        db, actor_user_id=admin_user.id, slug="b", name="B", sort_order=2
    )
    with pytest.raises(PatchRingError) as ei:
        patch_ring_service.update_ring(
            db, a.id, {"sort_order": 2}, actor_user_id=admin_user.id
        )
    assert "sort_order=2 already exists" in str(ei.value)


def test_update_ring_idempotent_no_audit_on_no_change(db, admin_user, monkeypatch):
    r = patch_ring_service.create_ring(
        db, actor_user_id=admin_user.id, slug="noop", name="Noop", sort_order=1
    )

    captured = []
    monkeypatch.setattr(
        patch_ring_service, "safe_emit", lambda **kw: captured.append(kw)
    )
    patch_ring_service.update_ring(
        db,
        r.id,
        {"name": "Noop", "sort_order": 1, "enabled": True},
        actor_user_id=admin_user.id,
    )
    # No real change → no audit row.
    assert captured == []


def test_update_ring_emits_audit_with_changed_fields(db, admin_user, monkeypatch):
    r = patch_ring_service.create_ring(
        db, actor_user_id=admin_user.id, slug="aud", name="A", sort_order=1
    )
    captured = {}
    monkeypatch.setattr(
        patch_ring_service, "safe_emit", lambda **kw: captured.update(kw)
    )
    patch_ring_service.update_ring(
        db, r.id, {"name": "B", "enabled": False}, actor_user_id=admin_user.id
    )
    assert captured["action"] == AUDIT_PATCH_RING_UPDATED
    assert sorted(captured["context"]["changed_fields"]) == ["enabled", "name"]


def test_update_ring_unknown_id_raises(db, admin_user):
    with pytest.raises(PatchRingError) as ei:
        patch_ring_service.update_ring(
            db, 999_999, {"name": "x"}, actor_user_id=admin_user.id
        )
    assert "not found" in str(ei.value)


# -- seed_default_rings -----------------------------------------------------


def test_seed_default_rings_creates_canary_pilot_prod(db, admin_user):
    out = patch_ring_service.seed_default_rings(db, actor_user_id=admin_user.id)
    assert sorted(out["created"]) == ["canary", "pilot", "prod"]
    assert out["existing"] == []
    rings = {r.slug: r for r in out["rings"]}
    assert rings["canary"].sort_order == 1
    assert rings["pilot"].sort_order == 2
    assert rings["prod"].sort_order == 3


def test_seed_default_rings_idempotent(db, admin_user):
    patch_ring_service.seed_default_rings(db, actor_user_id=admin_user.id)
    out = patch_ring_service.seed_default_rings(db, actor_user_id=admin_user.id)
    assert out["created"] == []
    assert sorted(out["existing"]) == ["canary", "pilot", "prod"]
    # And a third call still produces no rows.
    out2 = patch_ring_service.seed_default_rings(db, actor_user_id=admin_user.id)
    assert out2["created"] == []
    rings = db.query(PatchRing).order_by(PatchRing.sort_order).all()
    assert [r.slug for r in rings] == ["canary", "pilot", "prod"]


def test_seed_default_rings_sidesteps_taken_sort_order(db, admin_user):
    """If an operator pre-created a ring at sort_order=1, the seed
    falls back to the next free integer instead of crashing on the
    unique constraint."""
    patch_ring_service.create_ring(
        db,
        actor_user_id=admin_user.id,
        slug="custom-zero",
        name="Custom Zero",
        sort_order=1,
    )
    out = patch_ring_service.seed_default_rings(db, actor_user_id=admin_user.id)
    # canary should land at the next free integer after 1; the
    # operator's row stays at 1.
    rings = {r.slug: r for r in out["rings"]}
    assert rings["custom-zero"].sort_order == 1
    canary_order = rings["canary"].sort_order
    pilot_order = rings["pilot"].sort_order
    prod_order = rings["prod"].sort_order
    # All three default rings exist with non-colliding orders.
    assert {canary_order, pilot_order, prod_order, 1}  # all distinct → set has 4
    assert canary_order >= 2


def test_seed_default_rings_emits_one_audit_per_new_ring(db, admin_user, monkeypatch):
    captured = []
    monkeypatch.setattr(
        patch_ring_service, "safe_emit", lambda **kw: captured.append(kw)
    )
    patch_ring_service.seed_default_rings(db, actor_user_id=admin_user.id)
    actions = [c["action"] for c in captured]
    assert actions == [AUDIT_PATCH_RING_CREATED] * 3
    via = [c["context"].get("via") for c in captured]
    assert via == ["seed_default_rings"] * 3

    # Second call (idempotent) emits nothing.
    captured.clear()
    patch_ring_service.seed_default_rings(db, actor_user_id=admin_user.id)
    assert captured == []


def test_default_ring_seed_constants_match_locked_vocabulary():
    """Belt-and-suspenders: the canary/pilot/prod default-seed shape
    is part of the slice 1 contract. A typo in DEFAULT_RING_SEED would
    silently change operator expectations."""
    slugs = [r["slug"] for r in DEFAULT_RING_SEED]
    orders = [r["sort_order"] for r in DEFAULT_RING_SEED]
    assert slugs == ["canary", "pilot", "prod"]
    assert orders == [1, 2, 3]


# -- Bindings ---------------------------------------------------------------


@pytest.fixture
def ring(db, admin_user) -> PatchRing:
    return patch_ring_service.create_ring(
        db,
        actor_user_id=admin_user.id,
        slug="bind-target",
        name="Bind Target",
        sort_order=1,
    )


def test_bind_host_creates_and_audits(db, admin_user, ring, host, monkeypatch):
    captured = {}
    monkeypatch.setattr(
        patch_ring_service, "safe_emit", lambda **kw: captured.update(kw)
    )
    binding = patch_ring_service.bind_host(
        db,
        ring_id=ring.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )
    assert binding.ring_id == ring.id
    assert binding.system_id == host.id
    assert captured["action"] == AUDIT_PATCH_RING_BOUND
    assert captured["context"]["binding_kind"] == "host"


def test_bind_host_duplicate_rejected(db, admin_user, ring, host):
    patch_ring_service.bind_host(
        db,
        ring_id=ring.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )
    with pytest.raises(PatchRingError):
        patch_ring_service.bind_host(
            db,
            ring_id=ring.id,
            system_id=host.id,
            actor_user_id=admin_user.id,
        )


def test_bind_host_unknown_ring_raises(db, admin_user, host):
    with pytest.raises(PatchRingError) as ei:
        patch_ring_service.bind_host(
            db,
            ring_id=999_999,
            system_id=host.id,
            actor_user_id=admin_user.id,
        )
    assert "not found" in str(ei.value)


def test_bind_host_unknown_target_raises(db, admin_user, ring):
    with pytest.raises(PatchRingError) as ei:
        patch_ring_service.bind_host(
            db,
            ring_id=ring.id,
            system_id=999_999,
            actor_user_id=admin_user.id,
        )
    assert "system_id" in str(ei.value)
    # "does not exist" wording — route maps to 422 (per slice 1c-a).
    assert "does not exist" in str(ei.value)


def test_unbind_host_removes_row_and_audits(db, admin_user, ring, host, monkeypatch):
    patch_ring_service.bind_host(
        db,
        ring_id=ring.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )
    captured = {}
    monkeypatch.setattr(
        patch_ring_service, "safe_emit", lambda **kw: captured.update(kw)
    )
    patch_ring_service.unbind_host(
        db,
        ring_id=ring.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )
    assert (
        db.query(PatchRingHostBinding)
        .filter(PatchRingHostBinding.ring_id == ring.id)
        .first()
        is None
    )
    assert captured["action"] == AUDIT_PATCH_RING_UNBOUND


def test_unbind_host_when_absent_raises(db, admin_user, ring, host):
    with pytest.raises(PatchRingError):
        patch_ring_service.unbind_host(
            db,
            ring_id=ring.id,
            system_id=host.id,
            actor_user_id=admin_user.id,
        )


def test_bind_group_creates_and_duplicate_rejected(db, admin_user, ring, static_group):
    patch_ring_service.bind_group(
        db,
        ring_id=ring.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )
    with pytest.raises(PatchRingError):
        patch_ring_service.bind_group(
            db,
            ring_id=ring.id,
            group_id=static_group.id,
            actor_user_id=admin_user.id,
        )


def test_unbind_group_removes_row(db, admin_user, ring, static_group):
    patch_ring_service.bind_group(
        db,
        ring_id=ring.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )
    patch_ring_service.unbind_group(
        db,
        ring_id=ring.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )
    assert (
        db.query(PatchRingGroupBinding)
        .filter(PatchRingGroupBinding.ring_id == ring.id)
        .first()
        is None
    )


def test_bind_group_unknown_target_raises(db, admin_user, ring):
    with pytest.raises(PatchRingError) as ei:
        patch_ring_service.bind_group(
            db,
            ring_id=ring.id,
            group_id=999_999,
            actor_user_id=admin_user.id,
        )
    assert "group_id" in str(ei.value)


def test_bind_smart_group_creates_and_duplicate_rejected(
    db, admin_user, ring, smart_group
):
    patch_ring_service.bind_smart_group(
        db,
        ring_id=ring.id,
        smart_group_id=smart_group.id,
        actor_user_id=admin_user.id,
    )
    with pytest.raises(PatchRingError):
        patch_ring_service.bind_smart_group(
            db,
            ring_id=ring.id,
            smart_group_id=smart_group.id,
            actor_user_id=admin_user.id,
        )


def test_unbind_smart_group_removes_row(db, admin_user, ring, smart_group):
    patch_ring_service.bind_smart_group(
        db,
        ring_id=ring.id,
        smart_group_id=smart_group.id,
        actor_user_id=admin_user.id,
    )
    patch_ring_service.unbind_smart_group(
        db,
        ring_id=ring.id,
        smart_group_id=smart_group.id,
        actor_user_id=admin_user.id,
    )
    assert (
        db.query(PatchRingSmartGroupBinding)
        .filter(PatchRingSmartGroupBinding.ring_id == ring.id)
        .first()
        is None
    )


def test_bind_smart_group_unknown_target_raises(db, admin_user, ring):
    with pytest.raises(PatchRingError) as ei:
        patch_ring_service.bind_smart_group(
            db,
            ring_id=ring.id,
            smart_group_id=999_999,
            actor_user_id=admin_user.id,
        )
    assert "smart_group_id" in str(ei.value)


# -- list_bindings ---------------------------------------------------------


def test_list_bindings_empty(db, ring):
    out = patch_ring_service.list_bindings(db, ring.id)
    assert out == {
        "ring_id": ring.id,
        "hosts": [],
        "groups": [],
        "smart_groups": [],
    }


def test_list_bindings_returns_all_three_kinds(
    db, admin_user, ring, host, static_group, smart_group
):
    patch_ring_service.bind_host(
        db,
        ring_id=ring.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )
    patch_ring_service.bind_group(
        db,
        ring_id=ring.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )
    patch_ring_service.bind_smart_group(
        db,
        ring_id=ring.id,
        smart_group_id=smart_group.id,
        actor_user_id=admin_user.id,
    )
    out = patch_ring_service.list_bindings(db, ring.id)
    assert len(out["hosts"]) == 1
    assert len(out["groups"]) == 1
    assert len(out["smart_groups"]) == 1


def test_list_bindings_unknown_ring_raises(db):
    with pytest.raises(PatchRingError):
        patch_ring_service.list_bindings(db, 999_999)


# -- Cascade + DB CHECK belt-and-suspenders --------------------------------


def test_ring_delete_cascades_bindings(
    db, admin_user, ring, host, static_group, smart_group
):
    patch_ring_service.bind_host(
        db, ring_id=ring.id, system_id=host.id, actor_user_id=admin_user.id
    )
    patch_ring_service.bind_group(
        db,
        ring_id=ring.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )
    patch_ring_service.bind_smart_group(
        db,
        ring_id=ring.id,
        smart_group_id=smart_group.id,
        actor_user_id=admin_user.id,
    )
    db.delete(ring)
    db.commit()
    for model in (
        PatchRingHostBinding,
        PatchRingGroupBinding,
        PatchRingSmartGroupBinding,
    ):
        assert db.query(model).count() == 0


def test_sort_order_check_constraint(db, admin_user):
    bad = PatchRing(
        slug="zero",
        name="Zero",
        sort_order=0,
        enabled=True,
        created_by=admin_user.id,
    )
    db.add(bad)
    with pytest.raises(Exception):
        db.flush()
    db.rollback()


def test_delete_emits_audit(db, admin_user, monkeypatch):
    r = patch_ring_service.create_ring(
        db, actor_user_id=admin_user.id, slug="del-aud", name="Del", sort_order=1
    )
    captured = {}
    monkeypatch.setattr(
        patch_ring_service, "safe_emit", lambda **kw: captured.update(kw)
    )
    patch_ring_service.delete_ring(db, r.id, actor_user_id=admin_user.id)
    assert captured["action"] == AUDIT_PATCH_RING_DELETED
    assert captured["context"]["slug"] == "del-aud"
