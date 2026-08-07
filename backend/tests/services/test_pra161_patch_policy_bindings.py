"""PRA-161 slice 1c — patch_policy bindings service tests.

Covers the three sibling binding kinds (host / static-group /
smart-group), their CRUD, and the audit shape for
``patch_policy.bound`` / ``patch_policy.unbound``.

The effective-policy resolver is slice 1d and is NOT exercised here.
"""

from __future__ import annotations

import pytest

from app.db.models import (
    Credential,
    Group,
    PatchPolicy,
    PatchPolicyGroupBinding,
    PatchPolicyHostBinding,
    PatchPolicySmartGroupBinding,
    SmartGroup,
    System,
)
from app.services import patch_policy_service
from app.services.patch_policy_service import (
    AUDIT_PATCH_POLICY_BOUND,
    AUDIT_PATCH_POLICY_UNBOUND,
    PatchPolicyError,
)

# -- Fixtures ---------------------------------------------------------------


@pytest.fixture
def policy(db, admin_user) -> PatchPolicy:
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="weekly-security",
        name="Weekly Security",
        scope_kind="security_only",
    )


@pytest.fixture
def static_group(db) -> Group:
    g = db.query(Group).filter_by(name="bind-test-group").first()
    if g is None:
        g = Group(name="bind-test-group", description="t")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="bind-test-cred",
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
        hostname="host-bind-test.example.com",
        ip_address="10.0.0.10",
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
        name="bind-test-smart",
        description="t",
        rule_json="[]",
        enabled=True,
    )
    db.add(sg)
    db.flush()
    return sg


# -- bind_host --------------------------------------------------------------


def test_bind_host_creates_binding(db, admin_user, policy, host):
    binding = patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )
    assert binding.id is not None
    assert binding.policy_id == policy.id
    assert binding.system_id == host.id
    assert binding.created_by == admin_user.id


def test_bind_host_emits_audit(db, admin_user, policy, host, monkeypatch):
    captured = {}

    def fake_safe_emit(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(patch_policy_service, "safe_emit", fake_safe_emit)

    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
        actor_username="admin",
        actor_ip="10.0.0.1",
    )
    assert captured.get("action") == AUDIT_PATCH_POLICY_BOUND
    assert captured.get("target_kind") == "patch_policy"
    assert captured.get("target_id") == str(policy.id)
    ctx = captured.get("context") or {}
    assert ctx.get("policy_slug") == policy.slug
    assert ctx.get("binding_kind") == "host"
    assert ctx.get("target_id") == host.id
    assert "db" not in captured


def test_bind_host_duplicate_rejected(db, admin_user, policy, host):
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )
    with pytest.raises(PatchPolicyError) as ei:
        patch_policy_service.bind_host(
            db,
            policy_id=policy.id,
            system_id=host.id,
            actor_user_id=admin_user.id,
        )
    assert "already bound" in str(ei.value)


def test_bind_host_unknown_policy_raises(db, admin_user, host):
    with pytest.raises(PatchPolicyError) as ei:
        patch_policy_service.bind_host(
            db,
            policy_id=999_999,
            system_id=host.id,
            actor_user_id=admin_user.id,
        )
    assert "not found" in str(ei.value)


def test_bind_host_unknown_target_raises(db, admin_user, policy):
    with pytest.raises(PatchPolicyError) as ei:
        patch_policy_service.bind_host(
            db,
            policy_id=policy.id,
            system_id=999_999,
            actor_user_id=admin_user.id,
        )
    assert "system_id" in str(ei.value)


# -- unbind_host ------------------------------------------------------------


def test_unbind_host_removes_row(db, admin_user, policy, host):
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )
    patch_policy_service.unbind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )
    assert (
        db.query(PatchPolicyHostBinding)
        .filter(
            PatchPolicyHostBinding.policy_id == policy.id,
            PatchPolicyHostBinding.system_id == host.id,
        )
        .first()
        is None
    )


def test_unbind_host_emits_audit(db, admin_user, policy, host, monkeypatch):
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )
    captured = {}

    def fake_safe_emit(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(patch_policy_service, "safe_emit", fake_safe_emit)
    patch_policy_service.unbind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )
    assert captured.get("action") == AUDIT_PATCH_POLICY_UNBOUND
    ctx = captured.get("context") or {}
    assert ctx.get("binding_kind") == "host"


def test_unbind_host_when_no_binding_raises(db, admin_user, policy, host):
    with pytest.raises(PatchPolicyError) as ei:
        patch_policy_service.unbind_host(
            db,
            policy_id=policy.id,
            system_id=host.id,
            actor_user_id=admin_user.id,
        )
    assert "is not bound" in str(ei.value)


# -- bind_group / unbind_group ----------------------------------------------


def test_bind_group_creates_and_audits(
    db, admin_user, policy, static_group, monkeypatch
):
    captured = {}

    def fake_safe_emit(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(patch_policy_service, "safe_emit", fake_safe_emit)
    binding = patch_policy_service.bind_group(
        db,
        policy_id=policy.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )
    assert binding.policy_id == policy.id
    assert binding.group_id == static_group.id
    assert captured["action"] == AUDIT_PATCH_POLICY_BOUND
    assert captured["context"]["binding_kind"] == "group"
    assert captured["context"]["target_id"] == static_group.id


def test_bind_group_duplicate_rejected(db, admin_user, policy, static_group):
    patch_policy_service.bind_group(
        db,
        policy_id=policy.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )
    with pytest.raises(PatchPolicyError):
        patch_policy_service.bind_group(
            db,
            policy_id=policy.id,
            group_id=static_group.id,
            actor_user_id=admin_user.id,
        )


def test_bind_group_unknown_target_raises(db, admin_user, policy):
    with pytest.raises(PatchPolicyError) as ei:
        patch_policy_service.bind_group(
            db,
            policy_id=policy.id,
            group_id=999_999,
            actor_user_id=admin_user.id,
        )
    assert "group_id" in str(ei.value)


def test_unbind_group_removes_row(db, admin_user, policy, static_group):
    patch_policy_service.bind_group(
        db,
        policy_id=policy.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )
    patch_policy_service.unbind_group(
        db,
        policy_id=policy.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )
    assert (
        db.query(PatchPolicyGroupBinding)
        .filter(
            PatchPolicyGroupBinding.policy_id == policy.id,
            PatchPolicyGroupBinding.group_id == static_group.id,
        )
        .first()
        is None
    )


# -- bind_smart_group / unbind_smart_group ----------------------------------


def test_bind_smart_group_creates_and_audits(
    db, admin_user, policy, smart_group, monkeypatch
):
    captured = {}

    def fake_safe_emit(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(patch_policy_service, "safe_emit", fake_safe_emit)
    binding = patch_policy_service.bind_smart_group(
        db,
        policy_id=policy.id,
        smart_group_id=smart_group.id,
        actor_user_id=admin_user.id,
    )
    assert binding.smart_group_id == smart_group.id
    assert captured["context"]["binding_kind"] == "smart_group"


def test_bind_smart_group_duplicate_rejected(db, admin_user, policy, smart_group):
    patch_policy_service.bind_smart_group(
        db,
        policy_id=policy.id,
        smart_group_id=smart_group.id,
        actor_user_id=admin_user.id,
    )
    with pytest.raises(PatchPolicyError):
        patch_policy_service.bind_smart_group(
            db,
            policy_id=policy.id,
            smart_group_id=smart_group.id,
            actor_user_id=admin_user.id,
        )


def test_bind_smart_group_unknown_target_raises(db, admin_user, policy):
    with pytest.raises(PatchPolicyError) as ei:
        patch_policy_service.bind_smart_group(
            db,
            policy_id=policy.id,
            smart_group_id=999_999,
            actor_user_id=admin_user.id,
        )
    assert "smart_group_id" in str(ei.value)


def test_unbind_smart_group_removes_row(db, admin_user, policy, smart_group):
    patch_policy_service.bind_smart_group(
        db,
        policy_id=policy.id,
        smart_group_id=smart_group.id,
        actor_user_id=admin_user.id,
    )
    patch_policy_service.unbind_smart_group(
        db,
        policy_id=policy.id,
        smart_group_id=smart_group.id,
        actor_user_id=admin_user.id,
    )
    assert (
        db.query(PatchPolicySmartGroupBinding)
        .filter(
            PatchPolicySmartGroupBinding.policy_id == policy.id,
            PatchPolicySmartGroupBinding.smart_group_id == smart_group.id,
        )
        .first()
        is None
    )


# -- list_bindings ----------------------------------------------------------


def test_list_bindings_empty(db, policy):
    out = patch_policy_service.list_bindings(db, policy.id)
    assert out == {
        "policy_id": policy.id,
        "hosts": [],
        "groups": [],
        "smart_groups": [],
    }


def test_list_bindings_returns_all_three_kinds(
    db, admin_user, policy, host, static_group, smart_group
):
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )
    patch_policy_service.bind_group(
        db,
        policy_id=policy.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )
    patch_policy_service.bind_smart_group(
        db,
        policy_id=policy.id,
        smart_group_id=smart_group.id,
        actor_user_id=admin_user.id,
    )
    out = patch_policy_service.list_bindings(db, policy.id)
    assert len(out["hosts"]) == 1
    assert len(out["groups"]) == 1
    assert len(out["smart_groups"]) == 1


def test_list_bindings_unknown_policy_raises(db):
    with pytest.raises(PatchPolicyError):
        patch_policy_service.list_bindings(db, 999_999)


# -- Cross-binding semantics (slice-1c locks) -------------------------------


def test_two_distinct_policies_can_bind_same_host(db, admin_user, host):
    """At slice 1c, two distinct policies CAN both bind the same host
    directly. The resolver (slice 1d) is the one that turns this into
    a loud conflict — at the binding layer, this is just data."""
    p1 = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="p1",
        name="P1",
        scope_kind="security_only",
    )
    p2 = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="p2",
        name="P2",
        scope_kind="security_only",
    )
    patch_policy_service.bind_host(
        db, policy_id=p1.id, system_id=host.id, actor_user_id=admin_user.id
    )
    patch_policy_service.bind_host(
        db, policy_id=p2.id, system_id=host.id, actor_user_id=admin_user.id
    )
    rows = (
        db.query(PatchPolicyHostBinding)
        .filter(PatchPolicyHostBinding.system_id == host.id)
        .all()
    )
    assert {r.policy_id for r in rows} == {p1.id, p2.id}


def test_policy_delete_cascades_bindings(
    db, admin_user, policy, host, static_group, smart_group
):
    """ON DELETE CASCADE on policy_id — deleting the policy drops
    every binding kind without leaving orphans."""
    patch_policy_service.bind_host(
        db, policy_id=policy.id, system_id=host.id, actor_user_id=admin_user.id
    )
    patch_policy_service.bind_group(
        db,
        policy_id=policy.id,
        group_id=static_group.id,
        actor_user_id=admin_user.id,
    )
    patch_policy_service.bind_smart_group(
        db,
        policy_id=policy.id,
        smart_group_id=smart_group.id,
        actor_user_id=admin_user.id,
    )
    db.delete(policy)
    db.commit()
    for model in (
        PatchPolicyHostBinding,
        PatchPolicyGroupBinding,
        PatchPolicySmartGroupBinding,
    ):
        assert db.query(model).count() == 0
