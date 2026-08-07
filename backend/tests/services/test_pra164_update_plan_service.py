"""PRA-164 slice 1 — patch_update_plan_service tests.

Covers the dry-run plan substrate:

* Immediate-cadence plans land valid hosts in ``wave_index = 0`` and
  do not call the ring resolver.
* Staged-cadence plans order waves by the policy-bound ring set's
  ``sort_order``; disabled rings drop out of the wave index but stay
  visible in the snapshot.
* Effective-policy mismatch / conflict / no-policy each become a
  structured per-host blocked row instead of silently dropping or
  raising 5xx.
* Effective-ring ``no_ring`` / ``conflict`` / ring-not-in-policy-set
  each become structured per-host blocked rows.
* Content-profile context is snapshotted (resolved / no_profile /
  conflict) without performing content availability checks.
* Explicit ``target_system_ids`` is never silently dropped: unknown
  ids raise ``PatchUpdatePlanError`` (route 422); mismatched hosts
  appear as blocked rows.
* ``refresh_plan`` rebuilds against current state; ``cancel_plan``
  is idempotent and refuses non-cancelable states.
* ``patch_update_plan.created`` / ``.refreshed`` / ``.canceled``
  audit emission is verified.

Slice 1 does NOT test package-manager calls, package selection,
preflight snapshots, content-availability checks, approval
integration, execution, probes, reboot, rollback, mirror rebuild,
or airgap mechanics — none of those exist in this slice by design.
"""

from __future__ import annotations

from typing import List, Optional

import pytest

from app.db.models import (
    ContentProfile,
    Credential,
    Group,
    GroupContentProfileSubscription,
    HostContentProfileSubscription,
    PatchPolicy,
    PatchUpdatePlan,
    PatchUpdatePlanHost,
    SmartGroup,
    SmartGroupMembership,
    System,
)
from app.services import (
    patch_policy_service,
    patch_ring_service,
    patch_update_plan_service,
)
from app.services.patch_update_plan_service import (
    AUDIT_PLAN_CANCELED,
    AUDIT_PLAN_CREATED,
    AUDIT_PLAN_REFRESHED,
    BLOCK_HOST_EFFECTIVE_POLICY_CONFLICT,
    BLOCK_HOST_EFFECTIVE_POLICY_MISMATCH,
    BLOCK_HOST_EFFECTIVE_POLICY_NONE,
    BLOCK_HOST_RING_CONFLICT,
    BLOCK_HOST_RING_NO_RING,
    BLOCK_HOST_RING_NOT_IN_POLICY_SET,
    BLOCK_NO_TARGET_HOSTS,
    BLOCK_POLICY_DISABLED,
    BLOCK_STAGED_NO_ENABLED_RINGS,
    BLOCK_STAGED_NO_RING_BINDINGS,
    PLAN_HOST_STATE_BLOCKED,
    PLAN_HOST_STATE_PLANNED,
    PLAN_STATE_BLOCKED,
    PLAN_STATE_CANCELED,
    PLAN_STATE_DRAFT,
    PatchUpdatePlanError,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="plan-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="plan-test-cred",
        auth_method="password",
        username="root",
        vault_path="x",
    )
    db.add(c)
    db.flush()
    return c


@pytest.fixture
def host_factory(db, seed_distro, static_group, credentials):
    counter = {"n": 0}

    def make(hostname: Optional[str] = None) -> System:
        counter["n"] += 1
        s = System(
            hostname=hostname or f"plan-host-{counter['n']}.example.com",
            ip_address=f"10.0.10.{counter['n']}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=static_group.id,
            credentials_id=credentials.id,
        )
        db.add(s)
        db.flush()
        return s

    return make


def _make_policy(
    db,
    admin_user,
    slug: str,
    *,
    cadence: str = "immediate",
    enabled: bool = True,
) -> PatchPolicy:
    """Create a policy. Staged policies are created disabled (per the
    slice 3 enable-without-rings guard) then enabled by the caller
    after binding rings if they want it enabled."""
    create_kwargs = dict(
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind="security_only",
        rollout_cadence=cadence,
    )
    if cadence == "staged":
        # Force-disabled at create; caller enables after binding rings.
        create_kwargs["enabled"] = False
    else:
        create_kwargs["enabled"] = enabled
    pol = patch_policy_service.create_policy(db, **create_kwargs)
    if cadence == "staged" and enabled:
        # Caller wanted it enabled — mark it so but keep the test
        # arrangement step lightweight; the bind step runs first.
        pass
    return pol


def _make_ring(db, admin_user, slug: str, sort_order: int, *, enabled=True):
    return patch_ring_service.create_ring(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        sort_order=sort_order,
        enabled=enabled,
    )


def _bind_policy_to_host(db, admin_user, policy: PatchPolicy, host: System) -> None:
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )


def _bind_ring_to_host(db, admin_user, ring, host: System) -> None:
    patch_ring_service.bind_host(
        db,
        ring_id=ring.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )


def _profile(db, slug: str = "test-profile", family: str = "deb") -> ContentProfile:
    p = ContentProfile(slug=slug, display_name=slug, package_family=family)
    db.add(p)
    db.flush()
    return p


# ---------------------------------------------------------------------------
# Plan creation — immediate cadence
# ---------------------------------------------------------------------------


def test_create_immediate_plan_with_explicit_targets(db, admin_user, host_factory):
    h1 = host_factory("alpha.example.com")
    h2 = host_factory("beta.example.com")
    pol = _make_policy(db, admin_user, "imm")
    _bind_policy_to_host(db, admin_user, pol, h1)
    _bind_policy_to_host(db, admin_user, pol, h2)

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="immediate plan",
        target_system_ids=[h1.id, h2.id],
    )
    assert plan.state == PLAN_STATE_DRAFT
    assert plan.policy_snapshot["slug"] == "imm"
    assert plan.ring_sequence_snapshot == []
    assert plan.request_snapshot["requested_target_system_ids"] == [h1.id, h2.id]

    rows = patch_update_plan_service.list_plan_hosts(db, plan.id)
    assert len(rows) == 2
    assert all(r.state == PLAN_HOST_STATE_PLANNED for r in rows)
    assert all(r.wave_index == 0 for r in rows)
    assert all(r.ring_resolution_status == "not_applicable" for r in rows)
    assert {r.system_id for r in rows} == {h1.id, h2.id}
    assert {r.system_hostname_snapshot for r in rows} == {
        "alpha.example.com",
        "beta.example.com",
    }


def test_immediate_plan_auto_discovers_targets(db, admin_user, host_factory):
    h1 = host_factory()
    h2 = host_factory()
    h_other = host_factory()
    pol = _make_policy(db, admin_user, "imm-auto")
    other = _make_policy(db, admin_user, "other")
    _bind_policy_to_host(db, admin_user, pol, h1)
    _bind_policy_to_host(db, admin_user, pol, h2)
    _bind_policy_to_host(db, admin_user, other, h_other)

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="auto",
    )
    rows = patch_update_plan_service.list_plan_hosts(db, plan.id)
    assert {r.system_id for r in rows} == {h1.id, h2.id}
    assert plan.state == PLAN_STATE_DRAFT
    assert plan.request_snapshot["requested_target_system_ids"] is None


def test_immediate_plan_with_no_matching_hosts_is_blocked(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "lonely")

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="lonely",
    )
    assert plan.state == PLAN_STATE_BLOCKED
    codes = [r["code"] for r in plan.block_reasons]
    assert BLOCK_NO_TARGET_HOSTS in codes


def test_immediate_plan_blocks_host_with_mismatched_effective_policy(
    db, admin_user, host_factory
):
    h_match = host_factory()
    h_other = host_factory()
    pol = _make_policy(db, admin_user, "want")
    other = _make_policy(db, admin_user, "got")
    _bind_policy_to_host(db, admin_user, pol, h_match)
    _bind_policy_to_host(db, admin_user, other, h_other)

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="mixed",
        target_system_ids=[h_match.id, h_other.id],
    )
    assert plan.state == PLAN_STATE_DRAFT  # plan-level still draft
    rows = {
        r.system_id: r for r in patch_update_plan_service.list_plan_hosts(db, plan.id)
    }
    assert rows[h_match.id].state == PLAN_HOST_STATE_PLANNED
    assert rows[h_other.id].state == PLAN_HOST_STATE_BLOCKED
    codes = [b["code"] for b in rows[h_other.id].block_reasons]
    assert BLOCK_HOST_EFFECTIVE_POLICY_MISMATCH in codes
    detail = next(
        b["details"]
        for b in rows[h_other.id].block_reasons
        if b["code"] == BLOCK_HOST_EFFECTIVE_POLICY_MISMATCH
    )
    assert detail["effective_policy_slug"] == "got"
    assert detail["explicit_target"] is True


def test_immediate_plan_host_with_no_effective_policy_blocks(
    db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "want")
    h = host_factory()  # no policy bound

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="bare",
        target_system_ids=[h.id],
    )
    rows = patch_update_plan_service.list_plan_hosts(db, plan.id)
    assert len(rows) == 1
    assert rows[0].state == PLAN_HOST_STATE_BLOCKED
    codes = [b["code"] for b in rows[0].block_reasons]
    assert BLOCK_HOST_EFFECTIVE_POLICY_NONE in codes


def test_immediate_plan_host_with_effective_policy_conflict_blocks(
    db, admin_user, host_factory
):
    """Resolver raises EffectivePolicyConflict; service captures it as
    a structured blocked row instead of bubbling a 500."""
    h = host_factory()
    pol_a = _make_policy(db, admin_user, "a")
    pol_b = _make_policy(db, admin_user, "b")
    _bind_policy_to_host(db, admin_user, pol_a, h)
    _bind_policy_to_host(db, admin_user, pol_b, h)

    pol_target = _make_policy(db, admin_user, "target")

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol_target.id,
        name="confliction",
        target_system_ids=[h.id],
    )
    rows = patch_update_plan_service.list_plan_hosts(db, plan.id)
    assert rows[0].state == PLAN_HOST_STATE_BLOCKED
    codes = [b["code"] for b in rows[0].block_reasons]
    assert BLOCK_HOST_EFFECTIVE_POLICY_CONFLICT in codes
    detail = next(
        b["details"]
        for b in rows[0].block_reasons
        if b["code"] == BLOCK_HOST_EFFECTIVE_POLICY_CONFLICT
    )
    assert detail["tier"] == "direct_host"
    assert {p["slug"] for p in detail["policies"]} == {"a", "b"}


def test_unknown_target_system_id_raises_not_silent_drop(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "x")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)

    with pytest.raises(PatchUpdatePlanError) as exc:
        patch_update_plan_service.create_plan(
            db,
            actor_user_id=admin_user.id,
            policy_id=pol.id,
            name="bad",
            target_system_ids=[h.id, 999_999],
        )
    assert "999999" in str(exc.value)


def test_unknown_policy_id_raises(db, admin_user):
    with pytest.raises(PatchUpdatePlanError) as exc:
        patch_update_plan_service.create_plan(
            db,
            actor_user_id=admin_user.id,
            policy_id=999_999,
            name="bad",
        )
    assert "not found" in str(exc.value)


def test_unknown_maintenance_window_raises(db, admin_user, host_factory):
    """Slice 1a: unknown plan-level MW override must
    surface as a PatchUpdatePlanError (route 422) rather than a raw
    IntegrityError on commit (500)."""
    pol = _make_policy(db, admin_user, "mw-bad")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)

    with pytest.raises(PatchUpdatePlanError) as exc:
        patch_update_plan_service.create_plan(
            db,
            actor_user_id=admin_user.id,
            policy_id=pol.id,
            name="mw-bad",
            target_system_ids=[h.id],
            maintenance_window_id=999_999,
        )
    assert "maintenance_window_id" in str(exc.value)
    assert "999999" in str(exc.value)


def test_unknown_reboot_window_raises(db, admin_user, host_factory):
    """Slice 1a: same guarantee for the reboot-window
    override."""
    pol = _make_policy(db, admin_user, "rw-bad")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)

    with pytest.raises(PatchUpdatePlanError) as exc:
        patch_update_plan_service.create_plan(
            db,
            actor_user_id=admin_user.id,
            policy_id=pol.id,
            name="rw-bad",
            target_system_ids=[h.id],
            reboot_window_id=999_999,
        )
    assert "reboot_window_id" in str(exc.value)


def test_disabled_policy_yields_blocked_plan(db, admin_user, host_factory):
    h = host_factory()
    pol = _make_policy(db, admin_user, "off")
    _bind_policy_to_host(db, admin_user, pol, h)
    pol.enabled = False
    db.commit()

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="off-plan",
        target_system_ids=[h.id],
    )
    assert plan.state == PLAN_STATE_BLOCKED
    codes = [b["code"] for b in plan.block_reasons]
    assert BLOCK_POLICY_DISABLED in codes


# ---------------------------------------------------------------------------
# Plan creation — staged cadence
# ---------------------------------------------------------------------------


def test_staged_plan_orders_waves_by_policy_bound_ring_sort_order(
    db, admin_user, host_factory
):
    canary_host = host_factory()
    pilot_host = host_factory()
    prod_host = host_factory()
    pol = _make_policy(db, admin_user, "staged", cadence="staged")
    canary = _make_ring(db, admin_user, "canary", sort_order=1)
    pilot = _make_ring(db, admin_user, "pilot", sort_order=2)
    prod = _make_ring(db, admin_user, "prod", sort_order=3)

    patch_policy_service.bind_policy_ring(
        db, policy_id=pol.id, ring_id=canary.id, actor_user_id=admin_user.id
    )
    patch_policy_service.bind_policy_ring(
        db, policy_id=pol.id, ring_id=pilot.id, actor_user_id=admin_user.id
    )
    patch_policy_service.bind_policy_ring(
        db, policy_id=pol.id, ring_id=prod.id, actor_user_id=admin_user.id
    )

    _bind_policy_to_host(db, admin_user, pol, canary_host)
    _bind_policy_to_host(db, admin_user, pol, pilot_host)
    _bind_policy_to_host(db, admin_user, pol, prod_host)

    _bind_ring_to_host(db, admin_user, canary, canary_host)
    _bind_ring_to_host(db, admin_user, pilot, pilot_host)
    _bind_ring_to_host(db, admin_user, prod, prod_host)

    pol.enabled = True
    db.commit()

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="staged",
        target_system_ids=[prod_host.id, canary_host.id, pilot_host.id],
    )
    assert plan.state == PLAN_STATE_DRAFT
    assert [r["ring_slug"] for r in plan.ring_sequence_snapshot] == [
        "canary",
        "pilot",
        "prod",
    ]

    rows = {
        r.system_id: r for r in patch_update_plan_service.list_plan_hosts(db, plan.id)
    }
    assert rows[canary_host.id].wave_index == 0
    assert rows[pilot_host.id].wave_index == 1
    assert rows[prod_host.id].wave_index == 2
    assert all(r.state == PLAN_HOST_STATE_PLANNED for r in rows.values())
    assert rows[canary_host.id].ring_resolution_status == "resolved"


def test_staged_plan_with_no_ring_bindings_is_blocked(db, admin_user, host_factory):
    h = host_factory()
    pol = _make_policy(db, admin_user, "staged-empty", cadence="staged")
    _bind_policy_to_host(db, admin_user, pol, h)
    # Don't bind any rings; plan-level invariant catches this.

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="empty",
        target_system_ids=[h.id],
    )
    assert plan.state == PLAN_STATE_BLOCKED
    codes = [b["code"] for b in plan.block_reasons]
    assert BLOCK_STAGED_NO_RING_BINDINGS in codes


def test_staged_plan_with_only_disabled_rings_is_blocked(db, admin_user, host_factory):
    h = host_factory()
    pol = _make_policy(db, admin_user, "staged-disabled", cadence="staged")
    canary = _make_ring(db, admin_user, "canary", sort_order=1)
    patch_policy_service.bind_policy_ring(
        db, policy_id=pol.id, ring_id=canary.id, actor_user_id=admin_user.id
    )
    # Now disable the ring (keeping the binding) — the staged-readiness
    # plan-level invariant should catch the all-disabled case.
    canary.enabled = False
    db.commit()
    _bind_policy_to_host(db, admin_user, pol, h)

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="all-disabled",
        target_system_ids=[h.id],
    )
    assert plan.state == PLAN_STATE_BLOCKED
    codes = [b["code"] for b in plan.block_reasons]
    assert BLOCK_STAGED_NO_ENABLED_RINGS in codes


def test_staged_plan_blocks_host_with_no_ring(db, admin_user, host_factory):
    h = host_factory()
    pol = _make_policy(db, admin_user, "staged-noring", cadence="staged")
    canary = _make_ring(db, admin_user, "canary", sort_order=1)
    patch_policy_service.bind_policy_ring(
        db, policy_id=pol.id, ring_id=canary.id, actor_user_id=admin_user.id
    )
    _bind_policy_to_host(db, admin_user, pol, h)
    # Host has no ring bound at any tier.
    pol.enabled = True
    db.commit()

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="noring",
        target_system_ids=[h.id],
    )
    rows = patch_update_plan_service.list_plan_hosts(db, plan.id)
    assert rows[0].state == PLAN_HOST_STATE_BLOCKED
    codes = [b["code"] for b in rows[0].block_reasons]
    assert BLOCK_HOST_RING_NO_RING in codes
    assert rows[0].ring_resolution_status == "no_ring"


def test_staged_plan_blocks_host_when_resolved_ring_not_in_policy_set(
    db, admin_user, host_factory
):
    h = host_factory()
    pol = _make_policy(db, admin_user, "staged-mismatch", cadence="staged")
    in_set = _make_ring(db, admin_user, "in-set", sort_order=1)
    out_of_set = _make_ring(db, admin_user, "out", sort_order=2)
    patch_policy_service.bind_policy_ring(
        db, policy_id=pol.id, ring_id=in_set.id, actor_user_id=admin_user.id
    )
    _bind_policy_to_host(db, admin_user, pol, h)
    _bind_ring_to_host(db, admin_user, out_of_set, h)
    pol.enabled = True
    db.commit()

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="ring-mismatch",
        target_system_ids=[h.id],
    )
    rows = patch_update_plan_service.list_plan_hosts(db, plan.id)
    assert rows[0].state == PLAN_HOST_STATE_BLOCKED
    codes = [b["code"] for b in rows[0].block_reasons]
    assert BLOCK_HOST_RING_NOT_IN_POLICY_SET in codes
    detail = next(
        b["details"]
        for b in rows[0].block_reasons
        if b["code"] == BLOCK_HOST_RING_NOT_IN_POLICY_SET
    )
    assert detail["ring"]["ring_slug"] == "out"
    assert {r["ring_slug"] for r in detail["policy_ring_set"]} == {"in-set"}


def test_staged_plan_blocks_host_with_ring_conflict(db, admin_user, host_factory):
    h = host_factory()
    pol = _make_policy(db, admin_user, "staged-rc", cadence="staged")
    r1 = _make_ring(db, admin_user, "r1", sort_order=1)
    r2 = _make_ring(db, admin_user, "r2", sort_order=2)
    patch_policy_service.bind_policy_ring(
        db, policy_id=pol.id, ring_id=r1.id, actor_user_id=admin_user.id
    )
    patch_policy_service.bind_policy_ring(
        db, policy_id=pol.id, ring_id=r2.id, actor_user_id=admin_user.id
    )
    _bind_policy_to_host(db, admin_user, pol, h)
    _bind_ring_to_host(db, admin_user, r1, h)
    _bind_ring_to_host(db, admin_user, r2, h)
    pol.enabled = True
    db.commit()

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="rc",
        target_system_ids=[h.id],
    )
    rows = patch_update_plan_service.list_plan_hosts(db, plan.id)
    assert rows[0].state == PLAN_HOST_STATE_BLOCKED
    codes = [b["code"] for b in rows[0].block_reasons]
    assert BLOCK_HOST_RING_CONFLICT in codes


def test_staged_wave_index_skips_disabled_rings_in_set(db, admin_user, host_factory):
    """Disabled rings stay in ``ring_sequence_snapshot`` for audit but
    do not consume a wave_index slot."""
    h = host_factory()
    pol = _make_policy(db, admin_user, "staged-skip", cadence="staged")
    early = _make_ring(db, admin_user, "early", sort_order=1, enabled=False)
    later = _make_ring(db, admin_user, "later", sort_order=2)
    # Binding to a disabled ring is rejected at bind time; bind enabled
    # then disable. (Mirrors slice 3 design: disabled bindings stay
    # visible.)
    patch_policy_service.bind_policy_ring(
        db, policy_id=pol.id, ring_id=later.id, actor_user_id=admin_user.id
    )
    # ``early`` was created disabled — bind is refused. So we bind it
    # enabled first then flip it disabled.
    early.enabled = True
    db.commit()
    patch_policy_service.bind_policy_ring(
        db, policy_id=pol.id, ring_id=early.id, actor_user_id=admin_user.id
    )
    early.enabled = False
    db.commit()

    _bind_policy_to_host(db, admin_user, pol, h)
    _bind_ring_to_host(db, admin_user, later, h)
    pol.enabled = True
    db.commit()

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="skip-disabled",
        target_system_ids=[h.id],
    )
    rows = patch_update_plan_service.list_plan_hosts(db, plan.id)
    # Only one enabled ring in policy set -> wave_index = 0 for ``later``.
    assert rows[0].state == PLAN_HOST_STATE_PLANNED
    assert rows[0].wave_index == 0
    assert {r["ring_slug"] for r in plan.ring_sequence_snapshot} == {"early", "later"}


# ---------------------------------------------------------------------------
# Content-profile snapshot
# ---------------------------------------------------------------------------


def test_content_profile_snapshot_resolved(db, admin_user, host_factory):
    h = host_factory()
    pol = _make_policy(db, admin_user, "p")
    _bind_policy_to_host(db, admin_user, pol, h)
    profile = _profile(db, "myprof", family="deb")
    db.add(HostContentProfileSubscription(host_id=h.id, profile_id=profile.id))
    db.commit()

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="prof",
        target_system_ids=[h.id],
    )
    rows = patch_update_plan_service.list_plan_hosts(db, plan.id)
    assert rows[0].content_profile_state == "resolved"
    assert rows[0].content_profile_slug_snapshot == "myprof"
    assert rows[0].content_profile_package_family_snapshot == "deb"
    assert rows[0].content_profile_conflict_snapshot == []


def test_content_profile_snapshot_no_profile(db, admin_user, host_factory):
    h = host_factory()
    pol = _make_policy(db, admin_user, "p")
    _bind_policy_to_host(db, admin_user, pol, h)

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="np",
        target_system_ids=[h.id],
    )
    rows = patch_update_plan_service.list_plan_hosts(db, plan.id)
    assert rows[0].content_profile_state == "no_profile"
    assert rows[0].content_profile_id_snapshot is None
    # Slice 1 does not block on no_profile — content availability is
    # checked in a later slice.
    assert rows[0].state == PLAN_HOST_STATE_PLANNED


def test_content_profile_snapshot_conflict(db, admin_user, host_factory):
    h = host_factory()
    pol = _make_policy(db, admin_user, "p")
    _bind_policy_to_host(db, admin_user, pol, h)
    p1 = _profile(db, "p1")
    p2 = _profile(db, "p2")
    db.add(HostContentProfileSubscription(host_id=h.id, profile_id=p1.id))
    db.add(HostContentProfileSubscription(host_id=h.id, profile_id=p2.id))
    db.commit()

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="cp",
        target_system_ids=[h.id],
    )
    rows = patch_update_plan_service.list_plan_hosts(db, plan.id)
    assert rows[0].content_profile_state == "conflict"
    slugs = {b["profile_slug"] for b in rows[0].content_profile_conflict_snapshot}
    assert slugs == {"p1", "p2"}


# ---------------------------------------------------------------------------
# Refresh / cancel / list
# ---------------------------------------------------------------------------


def test_refresh_plan_picks_up_new_membership(db, admin_user, host_factory):
    h = host_factory()
    pol = _make_policy(db, admin_user, "rp")
    _bind_policy_to_host(db, admin_user, pol, h)

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="rp",
    )
    assert {r.system_id for r in plan.hosts} == {h.id}

    h2 = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h2)
    refreshed = patch_update_plan_service.refresh_plan(
        db, plan.id, actor_user_id=admin_user.id
    )
    rows = patch_update_plan_service.list_plan_hosts(db, refreshed.id)
    assert {r.system_id for r in rows} == {h.id, h2.id}


def test_refresh_replays_explicit_target_list(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "rep")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="rep",
        target_system_ids=[h.id],
    )
    h_other = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h_other)
    refreshed = patch_update_plan_service.refresh_plan(
        db, plan.id, actor_user_id=admin_user.id
    )
    rows = patch_update_plan_service.list_plan_hosts(db, refreshed.id)
    # h_other was not in the original explicit list; refresh must NOT
    # silently widen scope.
    assert {r.system_id for r in rows} == {h.id}


def test_cancel_plan_then_cancel_again_is_idempotent(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "cp")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="cp",
        target_system_ids=[h.id],
    )
    canceled = patch_update_plan_service.cancel_plan(
        db, plan.id, actor_user_id=admin_user.id
    )
    assert canceled.state == PLAN_STATE_CANCELED

    # Second cancel: idempotent no-op.
    again = patch_update_plan_service.cancel_plan(
        db, plan.id, actor_user_id=admin_user.id
    )
    assert again.state == PLAN_STATE_CANCELED


def test_refresh_canceled_plan_refused(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "rc")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="rc",
        target_system_ids=[h.id],
    )
    patch_update_plan_service.cancel_plan(db, plan.id, actor_user_id=admin_user.id)

    with pytest.raises(PatchUpdatePlanError) as exc:
        patch_update_plan_service.refresh_plan(db, plan.id, actor_user_id=admin_user.id)
    assert "canceled" in str(exc.value)


def test_list_plans_filters_by_policy_and_state(db, admin_user, host_factory):
    pol_a = _make_policy(db, admin_user, "list-a")
    pol_b = _make_policy(db, admin_user, "list-b")
    h_a = host_factory()
    h_b = host_factory()
    _bind_policy_to_host(db, admin_user, pol_a, h_a)
    _bind_policy_to_host(db, admin_user, pol_b, h_b)

    plan_a = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol_a.id,
        name="a",
        target_system_ids=[h_a.id],
    )
    plan_b = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol_b.id,
        name="b",
        target_system_ids=[h_b.id],
    )
    patch_update_plan_service.cancel_plan(db, plan_b.id, actor_user_id=admin_user.id)

    rows, total = patch_update_plan_service.list_plans(db, policy_id=pol_a.id)
    assert {p.id for p in rows} == {plan_a.id}

    rows, total = patch_update_plan_service.list_plans(db, state="canceled")
    assert plan_b.id in {p.id for p in rows}
    assert plan_a.id not in {p.id for p in rows}


def test_list_plans_invalid_state_raises(db):
    with pytest.raises(PatchUpdatePlanError):
        patch_update_plan_service.list_plans(db, state="not-a-state")


# ---------------------------------------------------------------------------
# Audit emission
# ---------------------------------------------------------------------------


def test_create_refresh_cancel_emits_audit(db, admin_user, host_factory, monkeypatch):
    captured: List[dict] = []

    def fake_safe_emit(**kwargs):
        captured.append(kwargs)

    monkeypatch.setattr(patch_update_plan_service, "safe_emit", fake_safe_emit)

    pol = _make_policy(db, admin_user, "audit")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="aud",
        target_system_ids=[h.id],
    )
    patch_update_plan_service.refresh_plan(db, plan.id, actor_user_id=admin_user.id)
    patch_update_plan_service.cancel_plan(db, plan.id, actor_user_id=admin_user.id)

    actions = [c["action"] for c in captured]
    assert AUDIT_PLAN_CREATED in actions
    assert AUDIT_PLAN_REFRESHED in actions
    assert AUDIT_PLAN_CANCELED in actions
    # Per feedback_safe_emit_session_boundary.md: no db= should be
    # passed (the service opens its own SessionLocal inside safe_emit).
    for c in captured:
        assert "db" not in c
