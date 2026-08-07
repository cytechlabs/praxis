"""PRA-164 slice 2 — package/advisory selection-preview service tests.

Covers the selection resolver wired into ``create_plan`` /
``refresh_plan``:

* `scope_kind = full` → every PackageUpdate becomes
  ``policy_full / selected``.
* `scope_kind = security_only` →
  - applicable advisory with matching ``PackageUpdate`` →
    ``policy_security_advisory / selected``.
  - applicable advisory without ``PackageUpdate`` candidate →
    ``no_available_update / unresolvable`` with structured details.
* `scope_kind = package_allowlist` →
  - allowlist entry with update → ``policy_allowlist_match / selected``.
  - allowlist entry without update → ``no_available_update /
    unresolvable`` (drift is visible).
* `scope_kind = package_denylist` →
  - name in denylist → ``policy_denylist_excluded / excluded``.
  - name not in denylist → ``policy_denylist_default_select /
    selected`` (the seventh enum value the migration adds beyond
    the spec's initial six per the slice packet's documented
    flexibility).
* inventory missing → single placeholder row with
  ``inventory_missing / unresolvable``.
* `blocked` plan hosts skip selection entirely.
* `selection_summary` is exact and refreshed deterministically
  (no stale rows after refresh).
* Cross-host leakage guard: a `PackageUpdate` for system A cannot
  appear under system B's plan-host selection rows.
* `patch_update_plan.selection_recomputed` audit emits exactly
  once per recomputation when ≥ 1 ``planned`` host was processed,
  with no `db=` argument; not emitted when every host is blocked.

Slice 2 reads only existing DB facts — `Package`, `PackageUpdate`,
`PatchAdvisoryHostApplicability`. No package-manager calls, SSH,
agent invocation, or live facts collection are exercised.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

import pytest

from app.db.models import (
    Credential,
    Group,
    Package,
    PackageUpdate,
    PatchAdvisory,
    PatchAdvisoryHostApplicability,
    PatchPolicy,
    PatchUpdatePlan,
    PatchUpdatePlanHost,
    PatchUpdatePlanSelectedPackage,
    System,
)
from app.services import patch_policy_service, patch_update_plan_service
from app.services.patch_update_plan_service import (
    AUDIT_PLAN_SELECTION_RECOMPUTED,
    INVENTORY_MISSING_PACKAGE_NAME,
    SELECTION_REASON_INVENTORY_MISSING,
    SELECTION_REASON_NO_AVAILABLE_UPDATE,
    SELECTION_REASON_POLICY_ALLOWLIST_MATCH,
    SELECTION_REASON_POLICY_DENYLIST_DEFAULT_SELECT,
    SELECTION_REASON_POLICY_DENYLIST_EXCLUDED,
    SELECTION_REASON_POLICY_FULL,
    SELECTION_REASON_POLICY_SECURITY_ADVISORY,
    SELECTION_STATE_EXCLUDED,
    SELECTION_STATE_SELECTED,
    SELECTION_STATE_UNRESOLVABLE,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="sel-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="sel-test-cred",
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
            hostname=hostname or f"sel-host-{counter['n']}.example.com",
            ip_address=f"10.0.30.{counter['n']}",
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


def _add_installed(db, system: System, name: str, version: str) -> Package:
    p = Package(
        system_id=system.id,
        name=name,
        installed_version=version,
        package_type="apt",
    )
    db.add(p)
    db.flush()
    return p


def _add_update(
    db,
    system: System,
    package: Package,
    available_version: str,
    update_type: str = "security",
) -> PackageUpdate:
    upd = PackageUpdate(
        package_id=package.id,
        system_id=system.id,
        available_version=available_version,
        update_type=update_type,
        discovered_on=datetime.utcnow(),
    )
    db.add(upd)
    db.flush()
    return upd


def _add_advisory(
    db,
    *,
    source_id: str,
    severity: str = "high",
    advisory_class: str = "security",
) -> PatchAdvisory:
    adv = PatchAdvisory(
        source_kind="ubuntu_usn",
        source_advisory_id=source_id,
        advisory_class=advisory_class,
        severity=severity,
        title=source_id,
        distro_family="debian",
        digest=source_id.lower(),
    )
    db.add(adv)
    db.flush()
    return adv


def _add_applicability(
    db,
    *,
    system: System,
    advisory: PatchAdvisory,
    package_name: str,
    installed_version: Optional[str] = None,
    required_version: Optional[str] = None,
    state: str = "applicable",
) -> PatchAdvisoryHostApplicability:
    row = PatchAdvisoryHostApplicability(
        system_id=system.id,
        advisory_id=advisory.id,
        package_name=package_name,
        installed_version=installed_version,
        required_version=required_version,
        state=state,
        evaluated_at=datetime.utcnow(),
    )
    db.add(row)
    db.flush()
    return row


def _make_policy(
    db,
    admin_user,
    slug: str,
    *,
    scope_kind: str = "security_only",
    scope_packages: Optional[List[str]] = None,
) -> PatchPolicy:
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind=scope_kind,
        scope_packages=scope_packages,
        rollout_cadence="immediate",
    )


def _bind_policy_to_host(db, admin_user, policy: PatchPolicy, host: System) -> None:
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )


def _selection_for(
    db, plan_id: int, plan_host_id: int
) -> List[PatchUpdatePlanSelectedPackage]:
    return (
        db.query(PatchUpdatePlanSelectedPackage)
        .filter(PatchUpdatePlanSelectedPackage.plan_host_id == plan_host_id)
        .order_by(
            PatchUpdatePlanSelectedPackage.state.asc(),
            PatchUpdatePlanSelectedPackage.package_name.asc(),
            PatchUpdatePlanSelectedPackage.advisory_id_snapshot.asc().nullsfirst(),
        )
        .all()
    )


# ---------------------------------------------------------------------------
# scope_kind = full
# ---------------------------------------------------------------------------


def test_scope_full_selects_every_package_update(db, admin_user, host_factory):
    h = host_factory()
    pol = _make_policy(db, admin_user, "sel-full", scope_kind="full")
    _bind_policy_to_host(db, admin_user, pol, h)

    p_a = _add_installed(db, h, "alpha", "1.0")
    p_b = _add_installed(db, h, "beta", "1.0")
    _add_update(db, h, p_a, "1.1", update_type="normal")
    _add_update(db, h, p_b, "2.0", update_type="security")

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="full",
        target_system_ids=[h.id],
    )
    host_row = patch_update_plan_service.list_plan_hosts(db, plan.id)[0]
    rows = _selection_for(db, plan.id, host_row.id)

    assert {r.package_name for r in rows} == {"alpha", "beta"}
    assert all(r.state == SELECTION_STATE_SELECTED for r in rows)
    assert all(r.selection_reason == SELECTION_REASON_POLICY_FULL for r in rows)
    assert all(r.advisory_id_snapshot is None for r in rows)
    assert host_row.selection_summary == {
        "selected": 2,
        "excluded": 0,
        "unresolvable": 0,
        "inventory_missing": False,
    }


# ---------------------------------------------------------------------------
# scope_kind = security_only
# ---------------------------------------------------------------------------


def test_scope_security_only_with_applicable_advisory_and_update(
    db, admin_user, host_factory
):
    h = host_factory()
    pol = _make_policy(db, admin_user, "sel-sec-ok", scope_kind="security_only")
    _bind_policy_to_host(db, admin_user, pol, h)

    pkg = _add_installed(db, h, "openssl", "1.0.0")
    _add_update(db, h, pkg, "1.0.1")
    adv = _add_advisory(db, source_id="USN-1234-1", severity="high")
    _add_applicability(
        db,
        system=h,
        advisory=adv,
        package_name="openssl",
        installed_version="1.0.0",
        required_version="1.0.1",
    )

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="sec-ok",
        target_system_ids=[h.id],
    )
    host_row = patch_update_plan_service.list_plan_hosts(db, plan.id)[0]
    rows = _selection_for(db, plan.id, host_row.id)

    assert len(rows) == 1
    row = rows[0]
    assert row.state == SELECTION_STATE_SELECTED
    assert row.selection_reason == SELECTION_REASON_POLICY_SECURITY_ADVISORY
    assert row.advisory_id_snapshot == adv.id
    assert row.advisory_severity_snapshot == "high"
    assert row.advisory_source_kind_snapshot == "ubuntu_usn"
    assert row.installed_version_snapshot == "1.0.0"
    assert row.available_version_snapshot == "1.0.1"
    assert row.details["advisory"]["source_advisory_id"] == "USN-1234-1"
    assert row.details["required_version"] == "1.0.1"


def test_scope_security_only_advisory_without_update_is_unresolvable(
    db, admin_user, host_factory
):
    h = host_factory()
    pol = _make_policy(db, admin_user, "sel-sec-na", scope_kind="security_only")
    _bind_policy_to_host(db, admin_user, pol, h)

    # Need at least one Package or PackageUpdate so we don't trip
    # the inventory-missing short-circuit.
    _add_installed(db, h, "filler", "1.0")
    pkg = _add_installed(db, h, "openssl", "1.0.0")
    _add_update(db, h, pkg, "1.0.1", update_type="normal")
    # Note: no PackageUpdate for ``libssl`` even though the advisory
    # targets it.

    adv = _add_advisory(db, source_id="USN-9999-1", severity="critical")
    _add_applicability(db, system=h, advisory=adv, package_name="libssl")

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="sec-na",
        target_system_ids=[h.id],
    )
    host_row = patch_update_plan_service.list_plan_hosts(db, plan.id)[0]
    rows = _selection_for(db, plan.id, host_row.id)

    by_pkg = {r.package_name: r for r in rows}
    assert by_pkg["libssl"].state == SELECTION_STATE_UNRESOLVABLE
    assert by_pkg["libssl"].selection_reason == SELECTION_REASON_NO_AVAILABLE_UPDATE
    assert by_pkg["libssl"].advisory_id_snapshot == adv.id
    assert "no PackageUpdate candidate" in by_pkg["libssl"].details["message"]


# ---------------------------------------------------------------------------
# scope_kind = package_allowlist
# ---------------------------------------------------------------------------


def test_scope_allowlist_match_and_drift(db, admin_user, host_factory):
    h = host_factory()
    pol = _make_policy(
        db,
        admin_user,
        "sel-allow",
        scope_kind="package_allowlist",
        scope_packages=["openssl", "missing-pkg"],
    )
    _bind_policy_to_host(db, admin_user, pol, h)

    pkg = _add_installed(db, h, "openssl", "1.0.0")
    _add_update(db, h, pkg, "1.0.1")
    # ``missing-pkg`` is in the allowlist but has no PackageUpdate.

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="allow",
        target_system_ids=[h.id],
    )
    host_row = patch_update_plan_service.list_plan_hosts(db, plan.id)[0]
    rows = _selection_for(db, plan.id, host_row.id)

    by_pkg = {r.package_name: r for r in rows}
    assert by_pkg["openssl"].state == SELECTION_STATE_SELECTED
    assert by_pkg["openssl"].selection_reason == SELECTION_REASON_POLICY_ALLOWLIST_MATCH
    assert by_pkg["missing-pkg"].state == SELECTION_STATE_UNRESOLVABLE
    assert (
        by_pkg["missing-pkg"].selection_reason == SELECTION_REASON_NO_AVAILABLE_UPDATE
    )


# ---------------------------------------------------------------------------
# scope_kind = package_denylist
# ---------------------------------------------------------------------------


def test_scope_denylist_excludes_only_denylisted_names(db, admin_user, host_factory):
    h = host_factory()
    pol = _make_policy(
        db,
        admin_user,
        "sel-deny",
        scope_kind="package_denylist",
        scope_packages=["frozen-pkg"],
    )
    _bind_policy_to_host(db, admin_user, pol, h)

    p_a = _add_installed(db, h, "frozen-pkg", "1.0")
    p_b = _add_installed(db, h, "free-pkg", "1.0")
    _add_update(db, h, p_a, "1.1")
    _add_update(db, h, p_b, "2.0")

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="deny",
        target_system_ids=[h.id],
    )
    host_row = patch_update_plan_service.list_plan_hosts(db, plan.id)[0]
    rows = _selection_for(db, plan.id, host_row.id)

    by_pkg = {r.package_name: r for r in rows}
    assert by_pkg["frozen-pkg"].state == SELECTION_STATE_EXCLUDED
    assert (
        by_pkg["frozen-pkg"].selection_reason
        == SELECTION_REASON_POLICY_DENYLIST_EXCLUDED
    )
    assert by_pkg["free-pkg"].state == SELECTION_STATE_SELECTED
    assert (
        by_pkg["free-pkg"].selection_reason
        == SELECTION_REASON_POLICY_DENYLIST_DEFAULT_SELECT
    )
    assert host_row.selection_summary == {
        "selected": 1,
        "excluded": 1,
        "unresolvable": 0,
        "inventory_missing": False,
    }


# ---------------------------------------------------------------------------
# Inventory-missing placeholder
# ---------------------------------------------------------------------------


def test_inventory_missing_writes_single_placeholder(db, admin_user, host_factory):
    h = host_factory()
    pol = _make_policy(db, admin_user, "sel-empty", scope_kind="full")
    _bind_policy_to_host(db, admin_user, pol, h)
    # Host has zero Package and zero PackageUpdate rows.

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="empty",
        target_system_ids=[h.id],
    )
    host_row = patch_update_plan_service.list_plan_hosts(db, plan.id)[0]
    rows = _selection_for(db, plan.id, host_row.id)

    assert len(rows) == 1
    placeholder = rows[0]
    assert placeholder.package_name == INVENTORY_MISSING_PACKAGE_NAME
    assert placeholder.state == SELECTION_STATE_UNRESOLVABLE
    assert placeholder.selection_reason == SELECTION_REASON_INVENTORY_MISSING
    assert host_row.selection_summary == {
        "selected": 0,
        "excluded": 0,
        "unresolvable": 1,
        "inventory_missing": True,
    }


# ---------------------------------------------------------------------------
# Blocked plan hosts skip selection
# ---------------------------------------------------------------------------


def test_blocked_plan_host_gets_no_selection_rows(db, admin_user, host_factory):
    """Effective-policy mismatch lands the host as ``blocked``;
    selection should NOT be computed for it (per the slice spec)."""
    h_match = host_factory()
    h_other = host_factory()
    pol = _make_policy(db, admin_user, "sel-blk-want", scope_kind="full")
    other = _make_policy(db, admin_user, "sel-blk-got", scope_kind="full")
    _bind_policy_to_host(db, admin_user, pol, h_match)
    _bind_policy_to_host(db, admin_user, other, h_other)

    pkg = _add_installed(db, h_other, "irrelevant", "1.0")
    _add_update(db, h_other, pkg, "1.1")

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="blk",
        target_system_ids=[h_match.id, h_other.id],
    )
    rows_by_host = {
        r.system_id: r for r in patch_update_plan_service.list_plan_hosts(db, plan.id)
    }
    blocked_host = rows_by_host[h_other.id]
    assert blocked_host.state == "blocked"
    assert _selection_for(db, plan.id, blocked_host.id) == []
    # Summary stays None for blocked hosts.
    assert blocked_host.selection_summary is None


# ---------------------------------------------------------------------------
# Refresh determinism + stale-row replacement
# ---------------------------------------------------------------------------


def test_refresh_deterministically_replaces_selection_rows(
    db, admin_user, host_factory
):
    h = host_factory()
    pol = _make_policy(db, admin_user, "sel-refresh", scope_kind="full")
    _bind_policy_to_host(db, admin_user, pol, h)

    pkg_a = _add_installed(db, h, "alpha", "1.0")
    upd_a = _add_update(db, h, pkg_a, "1.1")

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="refresh",
        target_system_ids=[h.id],
    )
    host_row = patch_update_plan_service.list_plan_hosts(db, plan.id)[0]
    initial_rows = _selection_for(db, plan.id, host_row.id)
    assert {r.package_name for r in initial_rows} == {"alpha"}

    # Drop the old PackageUpdate, add a new one for a different package.
    db.delete(upd_a)
    db.flush()
    pkg_b = _add_installed(db, h, "beta", "2.0")
    _add_update(db, h, pkg_b, "2.1")

    refreshed = patch_update_plan_service.refresh_plan(
        db, plan.id, actor_user_id=admin_user.id
    )
    new_host_row = patch_update_plan_service.list_plan_hosts(db, refreshed.id)[0]
    new_rows = _selection_for(db, refreshed.id, new_host_row.id)

    # Stale alpha selection must be gone; only beta remains.
    assert {r.package_name for r in new_rows} == {"beta"}
    assert new_host_row.selection_summary == {
        "selected": 1,
        "excluded": 0,
        "unresolvable": 0,
        "inventory_missing": False,
    }


# ---------------------------------------------------------------------------
# Cross-host leakage guard
# ---------------------------------------------------------------------------


def test_other_systems_package_updates_do_not_leak_into_preview(
    db, admin_user, host_factory
):
    """A PackageUpdate row whose ``system_id`` differs from the plan
    host must not appear under that host's selection rows."""
    h_target = host_factory()
    h_other = host_factory()
    pol = _make_policy(db, admin_user, "sel-leak", scope_kind="full")
    _bind_policy_to_host(db, admin_user, pol, h_target)

    p_target = _add_installed(db, h_target, "shared-name", "1.0")
    _add_update(db, h_target, p_target, "1.1")
    # Same package name on the other system, with a different version.
    p_other = _add_installed(db, h_other, "shared-name", "9.0")
    _add_update(db, h_other, p_other, "9.9")

    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="leak",
        target_system_ids=[h_target.id],
    )
    host_row = patch_update_plan_service.list_plan_hosts(db, plan.id)[0]
    rows = _selection_for(db, plan.id, host_row.id)

    assert len(rows) == 1
    assert rows[0].installed_version_snapshot == "1.0"
    assert rows[0].available_version_snapshot == "1.1"


# ---------------------------------------------------------------------------
# Audit emission
# ---------------------------------------------------------------------------


def test_selection_recomputed_audit_emits_once_with_aggregate(
    db, admin_user, host_factory, monkeypatch
):
    captured = []

    def fake_safe_emit(**kwargs):
        captured.append(kwargs)

    monkeypatch.setattr(patch_update_plan_service, "safe_emit", fake_safe_emit)

    h = host_factory()
    pol = _make_policy(db, admin_user, "sel-aud", scope_kind="full")
    _bind_policy_to_host(db, admin_user, pol, h)
    pkg = _add_installed(db, h, "alpha", "1.0")
    _add_update(db, h, pkg, "1.1")

    patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="aud",
        target_system_ids=[h.id],
    )

    sel_events = [c for c in captured if c["action"] == AUDIT_PLAN_SELECTION_RECOMPUTED]
    assert len(sel_events) == 1
    assert sel_events[0]["context"]["hosts_processed"] == 1
    assert sel_events[0]["context"]["selected_total"] == 1
    assert sel_events[0]["context"]["scope_kind"] == "full"
    # safe_emit session-boundary lock: no db= argument.
    assert "db" not in sel_events[0]


def test_selection_recomputed_audit_skipped_when_all_hosts_blocked(
    db, admin_user, host_factory, monkeypatch
):
    captured = []

    def fake_safe_emit(**kwargs):
        captured.append(kwargs)

    monkeypatch.setattr(patch_update_plan_service, "safe_emit", fake_safe_emit)

    h = host_factory()
    pol = _make_policy(db, admin_user, "sel-allblk-want", scope_kind="full")
    other = _make_policy(db, admin_user, "sel-allblk-got", scope_kind="full")
    _bind_policy_to_host(db, admin_user, other, h)
    # h's effective policy is `other`, but we plan against `pol`, so
    # h becomes a single blocked row -> nothing for selection to do.

    patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="allblk",
        target_system_ids=[h.id],
    )

    actions = [c["action"] for c in captured]
    assert AUDIT_PLAN_SELECTION_RECOMPUTED not in actions
