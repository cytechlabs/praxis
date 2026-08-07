"""PRA-161 slice 1b — patch_policy_service tests.

Covers CRUD, slug uniqueness, MW bind-time validation (exists /
enabled / schedule parses), scope-kind ↔ scope_packages cross-field
invariants, and the audit emission for ``patch_policy.created``.
"""

from __future__ import annotations

import json

import pytest

from app.db.models import MaintenanceWindow, PatchPolicy
from app.services import patch_policy_service
from app.services.patch_policy_service import (
    AUDIT_PATCH_POLICY_CREATED,
    PatchPolicyError,
)

# -- Fixtures ---------------------------------------------------------------


def _good_schedule() -> str:
    return json.dumps(
        {"day_of_week": [0, 1, 2, 3, 4], "start_time": "02:00", "end_time": "04:00"}
    )


@pytest.fixture
def enabled_window(db, admin_user) -> MaintenanceWindow:
    w = MaintenanceWindow(
        name="weeknights",
        target_type="all",
        target_id=None,
        schedule=_good_schedule(),
        enabled=True,
        created_by=admin_user.id,
    )
    db.add(w)
    db.commit()
    db.refresh(w)
    return w


@pytest.fixture
def disabled_window(db, admin_user) -> MaintenanceWindow:
    w = MaintenanceWindow(
        name="off",
        target_type="all",
        target_id=None,
        schedule=_good_schedule(),
        enabled=False,
        created_by=admin_user.id,
    )
    db.add(w)
    db.commit()
    db.refresh(w)
    return w


@pytest.fixture
def malformed_window(db, admin_user) -> MaintenanceWindow:
    w = MaintenanceWindow(
        name="busted",
        target_type="all",
        target_id=None,
        schedule="not-json",
        enabled=True,
        created_by=admin_user.id,
    )
    db.add(w)
    db.commit()
    db.refresh(w)
    return w


# -- create_policy ----------------------------------------------------------


def test_create_policy_minimal(db, admin_user):
    policy = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="weekly-security",
        name="Weekly Security",
        scope_kind="security_only",
    )
    assert policy.id is not None
    assert policy.slug == "weekly-security"
    assert policy.scope_kind == "security_only"
    assert policy.scope_packages == []
    assert policy.reboot_policy == "if_required"
    assert policy.rollout_cadence == "immediate"
    assert policy.failure_policy == "pause_fleet"
    assert policy.requires_approval is False
    assert policy.required_approvals == 1
    assert policy.enabled is True


def test_create_policy_emits_audit_event(db, admin_user, monkeypatch):
    """``patch_policy.created`` must be emitted via safe_emit AFTER
    the service's own commit (no ``db=`` so it opens its own session).
    """
    captured = {}

    def fake_safe_emit(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(patch_policy_service, "safe_emit", fake_safe_emit)

    patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        actor_username="admin",
        actor_ip="10.0.0.5",
        slug="staged-prod",
        name="Staged Prod",
        scope_kind="full",
        rollout_cadence="staged",
        # Slice 3 P1 guard: a fresh staged policy must start disabled
        # (no rings can exist yet). Test only verifies audit shape, so
        # disabled-draft is the right state.
        enabled=False,
    )

    assert captured.get("action") == AUDIT_PATCH_POLICY_CREATED
    assert captured.get("outcome") == "success"
    assert captured.get("actor_user_id") == admin_user.id
    assert captured.get("actor_username") == "admin"
    assert captured.get("actor_ip") == "10.0.0.5"
    assert captured.get("target_kind") == "patch_policy"
    assert captured.get("target_id") is not None
    ctx = captured.get("context") or {}
    assert ctx.get("slug") == "staged-prod"
    assert ctx.get("scope_kind") == "full"
    assert ctx.get("rollout_cadence") == "staged"
    # The lock: safe_emit is called WITHOUT db=, so it opens its own
    # SessionLocal (per feedback_safe_emit_session_boundary.md).
    assert "db" not in captured


def test_create_policy_slug_must_be_unique(db, admin_user):
    patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="dup",
        name="One",
        scope_kind="security_only",
    )
    with pytest.raises(PatchPolicyError):
        patch_policy_service.create_policy(
            db,
            actor_user_id=admin_user.id,
            slug="dup",
            name="Two",
            scope_kind="security_only",
        )


def test_create_policy_unknown_actor_rejected(db):
    with pytest.raises(PatchPolicyError):
        patch_policy_service.create_policy(
            db,
            actor_user_id=999_999,
            slug="x",
            name="X",
            scope_kind="security_only",
        )


# -- MW bind-time validation ------------------------------------------------


def test_create_policy_with_valid_window(db, admin_user, enabled_window):
    policy = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="with-window",
        name="With Window",
        scope_kind="security_only",
        maintenance_window_id=enabled_window.id,
    )
    assert policy.maintenance_window_id == enabled_window.id


def test_create_policy_rejects_nonexistent_window(db, admin_user):
    with pytest.raises(PatchPolicyError) as ei:
        patch_policy_service.create_policy(
            db,
            actor_user_id=admin_user.id,
            slug="ghost",
            name="Ghost",
            scope_kind="security_only",
            maintenance_window_id=999_999,
        )
    assert "does not reference an existing window" in str(ei.value)


def test_create_policy_rejects_disabled_window(db, admin_user, disabled_window):
    with pytest.raises(PatchPolicyError) as ei:
        patch_policy_service.create_policy(
            db,
            actor_user_id=admin_user.id,
            slug="off",
            name="Off",
            scope_kind="security_only",
            maintenance_window_id=disabled_window.id,
        )
    assert "disabled window" in str(ei.value)


def test_create_policy_rejects_malformed_schedule(db, admin_user, malformed_window):
    with pytest.raises(PatchPolicyError) as ei:
        patch_policy_service.create_policy(
            db,
            actor_user_id=admin_user.id,
            slug="busted",
            name="Busted",
            scope_kind="security_only",
            maintenance_window_id=malformed_window.id,
        )
    assert "malformed schedule" in str(ei.value)


@pytest.mark.parametrize(
    "schedule_json",
    [
        # Missing start_time
        json.dumps({"day_of_week": [0, 1, 2], "end_time": "04:00"}),
        # Missing end_time
        json.dumps({"day_of_week": [0, 1, 2], "start_time": "02:00"}),
        # Missing day_of_week
        json.dumps({"start_time": "02:00", "end_time": "04:00"}),
        # Empty day_of_week
        json.dumps({"day_of_week": [], "start_time": "02:00", "end_time": "04:00"}),
        # day_of_week entry out of range (high)
        json.dumps({"day_of_week": [7], "start_time": "02:00", "end_time": "04:00"}),
        # day_of_week entry out of range (negative)
        json.dumps({"day_of_week": [-1], "start_time": "02:00", "end_time": "04:00"}),
        # day_of_week entry non-int
        json.dumps(
            {"day_of_week": ["mon"], "start_time": "02:00", "end_time": "04:00"}
        ),
        # day_of_week entry True (bool-as-int trap)
        json.dumps({"day_of_week": [True], "start_time": "02:00", "end_time": "04:00"}),
        # start_time bad shape
        json.dumps({"day_of_week": [0], "start_time": "garbage", "end_time": "04:00"}),
        # start_time hour out of range
        json.dumps({"day_of_week": [0], "start_time": "25:00", "end_time": "04:00"}),
        # start_time minute out of range
        json.dumps({"day_of_week": [0], "start_time": "12:60", "end_time": "04:00"}),
        # end_time non-string
        '{"day_of_week": [0], "start_time": "02:00", "end_time": 400}',
        # Top-level not a dict
        json.dumps([{"day_of_week": [0]}]),
        # Not JSON at all
        "not-json",
        # Empty string
        "",
    ],
)
def test_create_policy_rejects_underspecified_schedule(db, admin_user, schedule_json):
    """Bind-time validator must reject any schedule shape the runtime
    would silently skip — otherwise a bound policy never enters its
    apply window. Slice 1b-a lock."""
    w = MaintenanceWindow(
        name="bind-trap",
        target_type="all",
        target_id=None,
        schedule=schedule_json,
        enabled=True,
        created_by=admin_user.id,
    )
    db.add(w)
    db.commit()
    db.refresh(w)
    with pytest.raises(PatchPolicyError) as ei:
        patch_policy_service.create_policy(
            db,
            actor_user_id=admin_user.id,
            slug="bind-trap",
            name="Bind Trap",
            scope_kind="security_only",
            maintenance_window_id=w.id,
        )
    assert "malformed schedule" in str(ei.value)


def test_create_policy_accepts_full_schedule(db, admin_user):
    """Sanity: a fully-specified, in-range schedule binds cleanly."""
    w = MaintenanceWindow(
        name="full-schedule",
        target_type="all",
        target_id=None,
        schedule=json.dumps(
            {
                "day_of_week": [0, 6],
                "start_time": "23:30",
                "end_time": "00:30",
            }
        ),
        enabled=True,
        created_by=admin_user.id,
    )
    db.add(w)
    db.commit()
    db.refresh(w)
    policy = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="full-schedule",
        name="Full",
        scope_kind="security_only",
        maintenance_window_id=w.id,
    )
    assert policy.maintenance_window_id == w.id


def test_create_policy_rejects_bad_reboot_window(db, admin_user, disabled_window):
    """Both reboot_window_id and maintenance_window_id are validated."""
    with pytest.raises(PatchPolicyError) as ei:
        patch_policy_service.create_policy(
            db,
            actor_user_id=admin_user.id,
            slug="reboot-bad",
            name="Reboot Bad",
            scope_kind="security_only",
            reboot_window_id=disabled_window.id,
        )
    assert "reboot_window_id" in str(ei.value)


# -- scope_kind ↔ scope_packages invariants ---------------------------------


@pytest.mark.parametrize("scope", ["security_only", "full"])
def test_security_or_full_rejects_packages(db, admin_user, scope):
    """Service-layer cross-field check (also enforced in pydantic; the
    service is the source of truth for direct callers like routes that
    pre-validated)."""
    with pytest.raises(PatchPolicyError):
        patch_policy_service.update_policy(
            db,
            _create_minimal(db, admin_user, "u1").id,
            {"scope_kind": scope, "scope_packages": ["openssl"]},
            actor_user_id=admin_user.id,
        )


@pytest.mark.parametrize("scope", ["package_allowlist", "package_denylist"])
def test_allowlist_denylist_requires_packages(db, admin_user, scope):
    with pytest.raises(PatchPolicyError):
        patch_policy_service.update_policy(
            db,
            _create_minimal(db, admin_user, "u2").id,
            {"scope_kind": scope, "scope_packages": []},
            actor_user_id=admin_user.id,
        )


# -- update_policy ----------------------------------------------------------


def _create_minimal(db, admin_user, slug):
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind="security_only",
    )


def test_update_policy_partial(db, admin_user):
    p = _create_minimal(db, admin_user, "u-partial")
    out = patch_policy_service.update_policy(
        db,
        p.id,
        {"name": "Renamed", "enabled": False},
        actor_user_id=admin_user.id,
    )
    assert out.name == "Renamed"
    assert out.enabled is False
    # Other fields untouched.
    assert out.scope_kind == "security_only"


def test_update_policy_rebind_window(db, admin_user, enabled_window):
    p = _create_minimal(db, admin_user, "u-bind")
    out = patch_policy_service.update_policy(
        db,
        p.id,
        {"maintenance_window_id": enabled_window.id},
        actor_user_id=admin_user.id,
    )
    assert out.maintenance_window_id == enabled_window.id


def test_update_policy_unbind_window(db, admin_user, enabled_window):
    p = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="u-unbind",
        name="Unbind",
        scope_kind="security_only",
        maintenance_window_id=enabled_window.id,
    )
    out = patch_policy_service.update_policy(
        db,
        p.id,
        {"maintenance_window_id": None},
        actor_user_id=admin_user.id,
    )
    assert out.maintenance_window_id is None


def test_update_policy_rejects_invalid_window(db, admin_user, disabled_window):
    p = _create_minimal(db, admin_user, "u-bad-bind")
    with pytest.raises(PatchPolicyError):
        patch_policy_service.update_policy(
            db,
            p.id,
            {"maintenance_window_id": disabled_window.id},
            actor_user_id=admin_user.id,
        )


def test_update_policy_unknown_id_raises(db, admin_user):
    with pytest.raises(PatchPolicyError) as ei:
        patch_policy_service.update_policy(
            db, 999_999, {"name": "x"}, actor_user_id=admin_user.id
        )
    assert "not found" in str(ei.value)


def test_update_policy_scope_kind_change_validates_packages(db, admin_user):
    """Switching from security_only to allowlist requires non-empty
    packages in the same update — and the inverse holds."""
    p = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="u-scope",
        name="Scope",
        scope_kind="package_allowlist",
        scope_packages=["openssl", "nginx"],
    )
    # Switch to security_only without clearing packages → rejected.
    with pytest.raises(PatchPolicyError):
        patch_policy_service.update_policy(
            db, p.id, {"scope_kind": "security_only"}, actor_user_id=admin_user.id
        )
    # Switch with explicit clear → accepted.
    out = patch_policy_service.update_policy(
        db,
        p.id,
        {"scope_kind": "security_only", "scope_packages": []},
        actor_user_id=admin_user.id,
    )
    assert out.scope_kind == "security_only"
    assert out.scope_packages == []


# -- list / get / delete ----------------------------------------------------


def test_list_policies_filters_and_paginates(db, admin_user):
    for i in range(5):
        patch_policy_service.create_policy(
            db,
            actor_user_id=admin_user.id,
            slug=f"l-{i}",
            name=f"L{i}",
            scope_kind="security_only",
            enabled=(i % 2 == 0),
        )
    rows, total = patch_policy_service.list_policies(db, enabled_only=False)
    assert total == 5
    assert len(rows) == 5
    enabled_rows, enabled_total = patch_policy_service.list_policies(
        db, enabled_only=True
    )
    assert enabled_total == 3
    assert all(r.enabled for r in enabled_rows)


def test_get_policy_by_slug_misses(db):
    assert patch_policy_service.get_policy_by_slug(db, "nope") is None


def test_delete_policy(db, admin_user):
    p = _create_minimal(db, admin_user, "u-del")
    patch_policy_service.delete_policy(db, p.id)
    assert db.query(PatchPolicy).filter(PatchPolicy.id == p.id).first() is None


def test_delete_unknown_policy_raises(db):
    with pytest.raises(PatchPolicyError):
        patch_policy_service.delete_policy(db, 999_999)


# -- DB CHECK belt-and-suspenders -------------------------------------------


def test_scope_kind_check_constraint(db, admin_user):
    """If service validation were bypassed, the DB CHECK still rejects
    unknown scope_kind values."""
    bad = PatchPolicy(
        slug="bad-scope",
        name="Bad",
        scope_kind="bogus",
        scope_packages=[],
        reboot_policy="never",
        rollout_cadence="immediate",
        failure_policy="continue",
        created_by=admin_user.id,
    )
    db.add(bad)
    with pytest.raises(Exception):
        db.flush()
    db.rollback()


def test_required_approvals_check_constraint(db, admin_user):
    bad = PatchPolicy(
        slug="bad-req",
        name="Bad Req",
        scope_kind="security_only",
        scope_packages=[],
        reboot_policy="never",
        rollout_cadence="immediate",
        failure_policy="continue",
        required_approvals=0,
        created_by=admin_user.id,
    )
    db.add(bad)
    with pytest.raises(Exception):
        db.flush()
    db.rollback()
