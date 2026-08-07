"""PRA-162 slice 3 — policy → ring-set binding + staged-readiness
service tests.

Covers:
* Bind / unbind happy paths and audit emission.
* Bind requires ``rollout_cadence='staged'``.
* New bindings to a disabled ring are rejected.
* Strict 422 on duplicate (policy_id, ring_id) — slice 1c convention.
* Last-enabled-ring guard on enabled staged policies.
* Disabled staged policies may be drained to empty (draft state).
* Existing bindings to a *later*-disabled ring stay visible.
* List ordering by ``sort_order`` then ``slug``.
* Staged-readiness vocabulary (not_staged / ready / missing_ring_set /
  no_enabled_rings).
* ``update_policy`` enable-without-rings guard.
* DB-level FK CASCADE on ring delete + policy delete.
"""

from __future__ import annotations

import pytest

from app.db.models import PatchPolicyRingBinding, PatchRing
from app.services import patch_policy_service, patch_ring_service
from app.services.patch_policy_service import (
    AUDIT_PATCH_POLICY_RING_BOUND,
    AUDIT_PATCH_POLICY_RING_UNBOUND,
    READINESS_MISSING_RING_SET,
    READINESS_NO_ENABLED_RINGS,
    READINESS_NOT_STAGED,
    READINESS_READY,
    PatchPolicyError,
)

# -- Helpers ---------------------------------------------------------------


def _make_policy(db, admin_user, slug, *, rollout_cadence="staged", enabled=False):
    """Default ``enabled=False`` for staged policies because slice 1f-a
    (and slice 3 P1) require staged policies to start as drafts: a
    fresh staged policy has no ring bindings yet, so it cannot be
    created enabled. Tests that want an *enabled* staged policy must
    bind an enabled ring first and then PATCH ``enabled=True``."""
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind="security_only",
        rollout_cadence=rollout_cadence,
        enabled=enabled,
    )


def _enable_policy(db, admin_user, policy):
    return patch_policy_service.update_policy(
        db, policy.id, {"enabled": True}, actor_user_id=admin_user.id
    )


def _make_ring(db, admin_user, slug, *, sort_order, enabled=True):
    return patch_ring_service.create_ring(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        sort_order=sort_order,
        enabled=enabled,
    )


# -- Bind happy path ------------------------------------------------------


def test_bind_policy_ring_creates_row(db, admin_user):
    policy = _make_policy(db, admin_user, "p-bind")
    ring = _make_ring(db, admin_user, "canary-bind", sort_order=1)

    binding = patch_policy_service.bind_policy_ring(
        db,
        policy_id=policy.id,
        ring_id=ring.id,
        actor_user_id=admin_user.id,
    )
    assert binding.id is not None
    assert binding.policy_id == policy.id
    assert binding.ring_id == ring.id


def test_bind_policy_ring_emits_audit(db, admin_user, monkeypatch):
    captured = {}

    def fake_safe_emit(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(patch_policy_service, "safe_emit", fake_safe_emit)

    policy = _make_policy(db, admin_user, "p-audit")
    ring = _make_ring(db, admin_user, "canary-audit", sort_order=1)
    captured.clear()

    patch_policy_service.bind_policy_ring(
        db,
        policy_id=policy.id,
        ring_id=ring.id,
        actor_user_id=admin_user.id,
        actor_username="admin",
        actor_ip="10.0.0.1",
    )
    assert captured["action"] == AUDIT_PATCH_POLICY_RING_BOUND
    assert captured["target_kind"] == "patch_policy"
    assert captured["target_id"] == str(policy.id)
    assert captured["context"]["ring_slug"] == ring.slug
    # safe_emit must be called with no db= argument (session boundary rule).
    assert "db" not in captured


# -- Bind validation ------------------------------------------------------


def test_bind_immediate_policy_rejected(db, admin_user):
    policy = _make_policy(db, admin_user, "p-imm", rollout_cadence="immediate")
    ring = _make_ring(db, admin_user, "for-imm", sort_order=1)

    with pytest.raises(PatchPolicyError) as exc:
        patch_policy_service.bind_policy_ring(
            db, policy_id=policy.id, ring_id=ring.id, actor_user_id=admin_user.id
        )
    assert "not staged" in str(exc.value)


def test_bind_disabled_ring_rejected(db, admin_user):
    policy = _make_policy(db, admin_user, "p-disabled-ring")
    ring = _make_ring(db, admin_user, "off", sort_order=1, enabled=False)

    with pytest.raises(PatchPolicyError) as exc:
        patch_policy_service.bind_policy_ring(
            db, policy_id=policy.id, ring_id=ring.id, actor_user_id=admin_user.id
        )
    assert "disabled" in str(exc.value)


def test_bind_unknown_policy_says_not_found(db, admin_user):
    ring = _make_ring(db, admin_user, "orphan", sort_order=1)
    with pytest.raises(PatchPolicyError) as exc:
        patch_policy_service.bind_policy_ring(
            db,
            policy_id=999_999,
            ring_id=ring.id,
            actor_user_id=admin_user.id,
        )
    assert "not found" in str(exc.value)


def test_bind_unknown_ring_says_does_not_exist(db, admin_user):
    policy = _make_policy(db, admin_user, "p-no-ring")
    with pytest.raises(PatchPolicyError) as exc:
        patch_policy_service.bind_policy_ring(
            db,
            policy_id=policy.id,
            ring_id=999_999,
            actor_user_id=admin_user.id,
        )
    msg = str(exc.value)
    assert "does not exist" in msg
    assert "not found" not in msg  # disambiguates 404 vs 422 at route layer


def test_bind_duplicate_strict_422(db, admin_user):
    policy = _make_policy(db, admin_user, "p-dup")
    ring = _make_ring(db, admin_user, "dup", sort_order=1)
    patch_policy_service.bind_policy_ring(
        db, policy_id=policy.id, ring_id=ring.id, actor_user_id=admin_user.id
    )
    with pytest.raises(PatchPolicyError) as exc:
        patch_policy_service.bind_policy_ring(
            db, policy_id=policy.id, ring_id=ring.id, actor_user_id=admin_user.id
        )
    assert "already bound" in str(exc.value)


# -- Unbind ---------------------------------------------------------------


def test_unbind_policy_ring_removes_row_and_audits(db, admin_user, monkeypatch):
    policy = _make_policy(db, admin_user, "p-unbind")
    ring_a = _make_ring(db, admin_user, "u-a", sort_order=1)
    ring_b = _make_ring(db, admin_user, "u-b", sort_order=2)
    patch_policy_service.bind_policy_ring(
        db, policy_id=policy.id, ring_id=ring_a.id, actor_user_id=admin_user.id
    )
    patch_policy_service.bind_policy_ring(
        db, policy_id=policy.id, ring_id=ring_b.id, actor_user_id=admin_user.id
    )

    captured = {}

    def fake_safe_emit(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(patch_policy_service, "safe_emit", fake_safe_emit)
    patch_policy_service.unbind_policy_ring(
        db, policy_id=policy.id, ring_id=ring_a.id, actor_user_id=admin_user.id
    )
    assert captured["action"] == AUDIT_PATCH_POLICY_RING_UNBOUND
    assert captured["context"]["ring_id"] == ring_a.id
    rows = patch_policy_service.list_policy_rings(db, policy.id)
    assert [r.id for _, r in rows] == [ring_b.id]


def test_unbind_unknown_pair_422(db, admin_user):
    policy = _make_policy(db, admin_user, "p-uu")
    ring = _make_ring(db, admin_user, "uu", sort_order=1)
    with pytest.raises(PatchPolicyError) as exc:
        patch_policy_service.unbind_policy_ring(
            db, policy_id=policy.id, ring_id=ring.id, actor_user_id=admin_user.id
        )
    assert "is not bound" in str(exc.value)


def test_unbind_last_enabled_ring_from_enabled_staged_policy_rejected(db, admin_user):
    policy = _make_policy(db, admin_user, "p-last")
    ring = _make_ring(db, admin_user, "last", sort_order=1)
    patch_policy_service.bind_policy_ring(
        db, policy_id=policy.id, ring_id=ring.id, actor_user_id=admin_user.id
    )
    _enable_policy(db, admin_user, policy)

    with pytest.raises(PatchPolicyError) as exc:
        patch_policy_service.unbind_policy_ring(
            db, policy_id=policy.id, ring_id=ring.id, actor_user_id=admin_user.id
        )
    assert "last enabled ring" in str(exc.value)


def test_unbind_last_ring_allowed_when_policy_disabled(db, admin_user):
    """Draft state: a disabled staged policy may be drained to empty."""
    policy = _make_policy(db, admin_user, "p-draft")  # already disabled
    ring = _make_ring(db, admin_user, "draft", sort_order=1)
    patch_policy_service.bind_policy_ring(
        db, policy_id=policy.id, ring_id=ring.id, actor_user_id=admin_user.id
    )

    patch_policy_service.unbind_policy_ring(
        db, policy_id=policy.id, ring_id=ring.id, actor_user_id=admin_user.id
    )
    assert patch_policy_service.list_policy_rings(db, policy.id) == []


def test_unbind_disabled_ring_does_not_trip_last_enabled_guard(db, admin_user):
    """Removing a *disabled* ring binding from an enabled staged policy
    should succeed even when no enabled rings remain after — the guard
    only fires when the *enabled-ring-being-removed* would leave zero
    remaining enabled rings."""
    policy = _make_policy(db, admin_user, "p-disabled-mix")
    enabled_ring = _make_ring(db, admin_user, "active", sort_order=1)
    other = _make_ring(db, admin_user, "later-off", sort_order=2)
    patch_policy_service.bind_policy_ring(
        db,
        policy_id=policy.id,
        ring_id=enabled_ring.id,
        actor_user_id=admin_user.id,
    )
    patch_policy_service.bind_policy_ring(
        db, policy_id=policy.id, ring_id=other.id, actor_user_id=admin_user.id
    )
    _enable_policy(db, admin_user, policy)
    other.enabled = False
    db.commit()

    # Removing the now-disabled binding should succeed.
    patch_policy_service.unbind_policy_ring(
        db, policy_id=policy.id, ring_id=other.id, actor_user_id=admin_user.id
    )
    rows = patch_policy_service.list_policy_rings(db, policy.id)
    assert [r.id for _, r in rows] == [enabled_ring.id]


# -- Stale binding visibility ---------------------------------------------


def test_existing_binding_to_later_disabled_ring_stays_visible(db, admin_user):
    policy = _make_policy(db, admin_user, "p-visible")
    ring_a = _make_ring(db, admin_user, "v-a", sort_order=1)
    ring_b = _make_ring(db, admin_user, "v-b", sort_order=2)
    patch_policy_service.bind_policy_ring(
        db, policy_id=policy.id, ring_id=ring_a.id, actor_user_id=admin_user.id
    )
    patch_policy_service.bind_policy_ring(
        db, policy_id=policy.id, ring_id=ring_b.id, actor_user_id=admin_user.id
    )
    ring_b.enabled = False
    db.commit()

    rows = patch_policy_service.list_policy_rings(db, policy.id)
    assert sorted(r.slug for _, r in rows) == ["v-a", "v-b"]


# -- Ordering --------------------------------------------------------------


def test_list_orders_by_sort_order_then_slug(db, admin_user):
    policy = _make_policy(db, admin_user, "p-order")
    a = _make_ring(db, admin_user, "z-low", sort_order=1)
    b = _make_ring(db, admin_user, "a-high", sort_order=2)
    c = _make_ring(db, admin_user, "m-mid", sort_order=3)
    for r in (b, a, c):
        patch_policy_service.bind_policy_ring(
            db, policy_id=policy.id, ring_id=r.id, actor_user_id=admin_user.id
        )

    rows = patch_policy_service.list_policy_rings(db, policy.id)
    assert [r.slug for _, r in rows] == ["z-low", "a-high", "m-mid"]


# -- Staged readiness ------------------------------------------------------


def test_readiness_immediate_policy_is_not_staged(db, admin_user):
    policy = _make_policy(db, admin_user, "r-imm", rollout_cadence="immediate")
    res = patch_policy_service.get_staged_readiness(db, policy.id)
    assert res["status"] == READINESS_NOT_STAGED
    assert res["ring_count"] == 0
    assert res["enabled_ring_count"] == 0


def test_readiness_staged_with_enabled_ring_is_ready(db, admin_user):
    policy = _make_policy(db, admin_user, "r-ready")
    ring = _make_ring(db, admin_user, "r-r", sort_order=1)
    patch_policy_service.bind_policy_ring(
        db, policy_id=policy.id, ring_id=ring.id, actor_user_id=admin_user.id
    )
    res = patch_policy_service.get_staged_readiness(db, policy.id)
    assert res["status"] == READINESS_READY
    assert res["ring_count"] == 1
    assert res["enabled_ring_count"] == 1


def test_readiness_staged_with_no_rings_is_missing_ring_set(db, admin_user):
    # Disabled is the only legal state for a staged policy without rings.
    policy = _make_policy(db, admin_user, "r-empty")
    res = patch_policy_service.get_staged_readiness(db, policy.id)
    assert res["status"] == READINESS_MISSING_RING_SET
    assert res["enabled_ring_count"] == 0


def test_readiness_staged_with_only_disabled_rings_is_no_enabled_rings(db, admin_user):
    policy = _make_policy(db, admin_user, "r-stale")
    ring = _make_ring(db, admin_user, "r-stale-ring", sort_order=1)
    patch_policy_service.bind_policy_ring(
        db, policy_id=policy.id, ring_id=ring.id, actor_user_id=admin_user.id
    )
    ring.enabled = False
    db.commit()

    res = patch_policy_service.get_staged_readiness(db, policy.id)
    assert res["status"] == READINESS_NO_ENABLED_RINGS
    assert res["ring_count"] == 1
    assert res["enabled_ring_count"] == 0


def test_readiness_unknown_policy_raises(db):
    with pytest.raises(PatchPolicyError):
        patch_policy_service.get_staged_readiness(db, 999_999)


# -- update_policy enable-without-rings guard ------------------------------


def test_update_cannot_enable_staged_policy_without_rings(db, admin_user):
    policy = _make_policy(db, admin_user, "u-empty", enabled=False)
    with pytest.raises(PatchPolicyError) as exc:
        patch_policy_service.update_policy(
            db,
            policy.id,
            {"enabled": True},
            actor_user_id=admin_user.id,
        )
    assert "no enabled bound rings" in str(exc.value)


def test_update_cannot_transition_immediate_to_staged_while_enabled_without_rings(
    db, admin_user
):
    # Immediate policies are legally enabled-without-rings; the guard
    # bites only when the *post-update* state is enabled+staged.
    policy = _make_policy(
        db,
        admin_user,
        "u-imm-to-staged",
        rollout_cadence="immediate",
        enabled=True,
    )
    with pytest.raises(PatchPolicyError):
        patch_policy_service.update_policy(
            db,
            policy.id,
            {"rollout_cadence": "staged"},
            actor_user_id=admin_user.id,
        )


def test_update_can_disable_staged_policy_without_rings(db, admin_user):
    """Disabling a staged policy is allowed even with zero rings — the
    guard only fires when the post-update state is enabled+staged."""
    policy = _make_policy(db, admin_user, "u-can-disable", enabled=False)
    # Already disabled — confirm the no-op update doesn't raise.
    patch_policy_service.update_policy(
        db, policy.id, {"description": "draft"}, actor_user_id=admin_user.id
    )


def test_update_cannot_remove_rings_via_staged_enable(db, admin_user):
    """Even with a ring bound, enabling must succeed; this is the
    inverse case to confirm we did not over-restrict the guard."""
    policy = _make_policy(db, admin_user, "u-ok", enabled=False)
    ring = _make_ring(db, admin_user, "u-ok-ring", sort_order=1)
    patch_policy_service.bind_policy_ring(
        db, policy_id=policy.id, ring_id=ring.id, actor_user_id=admin_user.id
    )
    # Now enable — should succeed.
    patch_policy_service.update_policy(
        db, policy.id, {"enabled": True}, actor_user_id=admin_user.id
    )


# -- DB-level FK CASCADE --------------------------------------------------


def test_policy_delete_cascades_ring_bindings(db, admin_user):
    # Policy stays disabled (default for staged) so delete is unblocked.
    policy = _make_policy(db, admin_user, "p-cascade")
    ring = _make_ring(db, admin_user, "cas", sort_order=1)
    patch_policy_service.bind_policy_ring(
        db, policy_id=policy.id, ring_id=ring.id, actor_user_id=admin_user.id
    )
    patch_policy_service.delete_policy(db, policy.id)

    remaining = (
        db.query(PatchPolicyRingBinding)
        .filter(PatchPolicyRingBinding.policy_id == policy.id)
        .count()
    )
    assert remaining == 0


def test_ring_delete_cascades_policy_ring_bindings(db, admin_user):
    """Deleting a ring removes its policy bindings via FK CASCADE so
    a stale (policy_id, ring_id) row never points to a non-existent
    ring."""
    policy = _make_policy(db, admin_user, "p-cas2")
    ring = _make_ring(db, admin_user, "cas2", sort_order=1)
    patch_policy_service.bind_policy_ring(
        db, policy_id=policy.id, ring_id=ring.id, actor_user_id=admin_user.id
    )

    patch_ring_service.delete_ring(db, ring.id, actor_user_id=admin_user.id)

    remaining = (
        db.query(PatchPolicyRingBinding)
        .filter(PatchPolicyRingBinding.policy_id == policy.id)
        .count()
    )
    assert remaining == 0


# -- Slice 3-a regression: P1 create-time guard, P2 staged→immediate guard


def test_create_enabled_staged_policy_rejected_p1(db, admin_user):
    """A fresh staged policy has no rings yet by
    definition, so create_policy(enabled=True, rollout_cadence='staged')
    must be rejected. Operators must create disabled, bind, then enable."""
    with pytest.raises(PatchPolicyError) as exc:
        patch_policy_service.create_policy(
            db,
            actor_user_id=admin_user.id,
            slug="p1-enabled-staged",
            name="enabled staged",
            scope_kind="security_only",
            rollout_cadence="staged",
            enabled=True,
        )
    msg = str(exc.value)
    assert "enabled staged policy" in msg
    assert "without ring bindings" in msg


def test_create_disabled_staged_policy_allowed(db, admin_user):
    """Confirm the P1 guard is not over-restrictive: disabled staged is
    the legal draft state and must still create cleanly."""
    policy = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="p1-disabled-staged",
        name="draft staged",
        scope_kind="security_only",
        rollout_cadence="staged",
        enabled=False,
    )
    assert policy.id is not None
    assert policy.enabled is False
    assert policy.rollout_cadence == "staged"


def test_create_enabled_immediate_policy_allowed(db, admin_user):
    """Confirm immediate is unaffected by the P1 guard."""
    policy = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="p1-imm",
        name="imm",
        scope_kind="security_only",
        rollout_cadence="immediate",
        enabled=True,
    )
    assert policy.enabled is True


def test_update_staged_to_immediate_with_bindings_rejected_p2(db, admin_user):
    """Rolling staged → immediate while ring bindings
    still exist would orphan the bindings. Reject so the operator
    unbinds explicitly and the audit trail records each removal."""
    policy = _make_policy(db, admin_user, "p2-staged")
    ring = _make_ring(db, admin_user, "p2-ring", sort_order=1)
    patch_policy_service.bind_policy_ring(
        db, policy_id=policy.id, ring_id=ring.id, actor_user_id=admin_user.id
    )

    with pytest.raises(PatchPolicyError) as exc:
        patch_policy_service.update_policy(
            db,
            policy.id,
            {"rollout_cadence": "immediate"},
            actor_user_id=admin_user.id,
        )
    msg = str(exc.value)
    assert "to immediate" in msg
    assert "ring bindings" in msg


def test_update_staged_to_immediate_after_unbinding_allowed_p2(db, admin_user):
    """After explicit unbind, the staged→immediate transition succeeds.
    This proves the P2 guard is not a one-way trap."""
    policy = _make_policy(db, admin_user, "p2-clean")
    ring = _make_ring(db, admin_user, "p2-clean-ring", sort_order=1)
    patch_policy_service.bind_policy_ring(
        db, policy_id=policy.id, ring_id=ring.id, actor_user_id=admin_user.id
    )
    # Policy is disabled (draft) so unbinding the only ring is allowed.
    patch_policy_service.unbind_policy_ring(
        db, policy_id=policy.id, ring_id=ring.id, actor_user_id=admin_user.id
    )

    patch_policy_service.update_policy(
        db,
        policy.id,
        {"rollout_cadence": "immediate"},
        actor_user_id=admin_user.id,
    )
    refreshed = patch_policy_service.get_policy(db, policy.id)
    assert refreshed.rollout_cadence == "immediate"


def test_update_immediate_to_staged_without_rings_disabled_allowed(db, admin_user):
    """Inverse direction: immediate → staged on a *disabled* policy
    is legal even with no rings (it becomes a draft). Confirms we did
    not break the disabled-as-draft path while adding the P2 guard."""
    policy = _make_policy(
        db, admin_user, "imm-to-staged-draft", rollout_cadence="immediate"
    )
    patch_policy_service.update_policy(
        db,
        policy.id,
        {"rollout_cadence": "staged"},
        actor_user_id=admin_user.id,
    )
    refreshed = patch_policy_service.get_policy(db, policy.id)
    assert refreshed.rollout_cadence == "staged"
    assert refreshed.enabled is False
