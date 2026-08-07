"""PRA-165 slice 1 — compliance_service tests.

Covers:

* Policy CRUD + slug uniqueness + enable/disable + delete-built-in guard.
* Check CRUD + kind validation + definition shape validation.
* Idempotent starter-pack seed (re-running seeds nothing new).
* Audit emission shape (safe_emit AFTER own commit, no ``db=``).
* Slice 1 non-execution boundary — no service path executes probes,
  no facts/package/SSH service is invoked.
"""

from __future__ import annotations

import pytest

from app.db.models import CompliancePolicy, CompliancePolicyCheck
from app.services import compliance_service
from app.services.compliance_service import (
    AUDIT_COMPLIANCE_CHECK_CREATED,
    AUDIT_COMPLIANCE_CHECK_DELETED,
    AUDIT_COMPLIANCE_CHECK_UPDATED,
    AUDIT_COMPLIANCE_POLICY_CREATED,
    AUDIT_COMPLIANCE_POLICY_DELETED,
    AUDIT_COMPLIANCE_POLICY_DISABLED,
    AUDIT_COMPLIANCE_POLICY_ENABLED,
    AUDIT_COMPLIANCE_POLICY_UPDATED,
    AUDIT_COMPLIANCE_STARTER_PACK_SEEDED,
    KNOWN_CHECK_KINDS,
    RUNNER_OWNER_PRA166,
    RUNNER_OWNER_SLICE_2,
    RUNNER_STATUS_NOT_IMPLEMENTED,
    ComplianceError,
)
from app.services.compliance_starter_pack import STARTER_PACK

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class AuditCapture:
    """Collects safe_emit invocations as a list of kwargs dicts."""

    def __init__(self):
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)

    def actions(self):
        return [c["action"] for c in self.calls]

    def by_action(self, action):
        return [c for c in self.calls if c["action"] == action]


@pytest.fixture
def capture_audit(monkeypatch):
    cap = AuditCapture()
    monkeypatch.setattr(compliance_service, "safe_emit", cap)
    return cap


# ---------------------------------------------------------------------------
# Policy CRUD
# ---------------------------------------------------------------------------


def test_create_policy_minimal(db, admin_user):
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="ssh-baseline",
        name="SSH Baseline",
    )
    assert policy.id is not None
    assert policy.slug == "ssh-baseline"
    assert policy.severity == "medium"
    assert policy.category == "custom"
    assert policy.enabled is True
    assert policy.built_in is False
    assert policy.starter_pack_key is None
    assert policy.version == 1


def test_create_policy_emits_audit_with_session_boundary(db, admin_user, capture_audit):
    """``compliance_policy.created`` must be emitted via safe_emit
    AFTER the service commits (no ``db=`` so safe_emit opens its own
    SessionLocal).
    """
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        actor_username="admin",
        actor_ip="10.0.0.5",
        slug="kernel-baseline",
        name="Kernel Baseline",
        severity="high",
        category="kernel",
    )
    created = capture_audit.by_action(AUDIT_COMPLIANCE_POLICY_CREATED)
    assert len(created) == 1
    call = created[0]
    assert call["outcome"] == "success"
    assert call["actor_user_id"] == admin_user.id
    assert call["actor_username"] == "admin"
    assert call["actor_ip"] == "10.0.0.5"
    assert call["target_kind"] == "compliance_policy"
    assert call["target_id"] == str(policy.id)
    ctx = call["context"]
    assert ctx["policy_slug"] == "kernel-baseline"
    assert ctx["severity"] == "high"
    assert ctx["enabled"] is True
    # Session-boundary lock: safe_emit is called WITHOUT db= so it
    # opens its own SessionLocal.
    assert "db" not in call


def test_create_policy_rejects_bad_slug(db, admin_user):
    with pytest.raises(ComplianceError):
        compliance_service.create_policy(
            db,
            actor_user_id=admin_user.id,
            slug="UPPERCASE-NOT-OK",
            name="Bad Slug",
        )


def test_create_policy_rejects_duplicate_slug(db, admin_user):
    compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="dup",
        name="One",
    )
    with pytest.raises(ComplianceError) as ei:
        compliance_service.create_policy(
            db,
            actor_user_id=admin_user.id,
            slug="dup",
            name="Two",
        )
    assert "already exists" in str(ei.value)


def test_create_policy_rejects_unknown_actor(db):
    with pytest.raises(ComplianceError):
        compliance_service.create_policy(
            db,
            actor_user_id=999_999,
            slug="x",
            name="X",
        )


def test_create_policy_rejects_invalid_severity(db, admin_user):
    with pytest.raises(ComplianceError):
        compliance_service.create_policy(
            db,
            actor_user_id=admin_user.id,
            slug="bad-sev",
            name="Bad Severity",
            severity="catastrophic",
        )


def test_create_policy_rejects_zero_or_negative_interval(db, admin_user):
    with pytest.raises(ComplianceError):
        compliance_service.create_policy(
            db,
            actor_user_id=admin_user.id,
            slug="bad-interval",
            name="Bad Interval",
            schedule_interval_hours=0,
        )


def test_create_policy_rejects_bool_as_interval(db, admin_user):
    """``bool`` is a subclass of ``int``; reject so True/False don't
    silently mean 1/0 hours (bool-as-int defense)."""
    with pytest.raises(ComplianceError):
        compliance_service.create_policy(
            db,
            actor_user_id=admin_user.id,
            slug="bool-interval",
            name="Bool Interval",
            schedule_interval_hours=True,  # type: ignore[arg-type]
        )


def test_list_policies_filters(db, admin_user):
    compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug="a", name="A", enabled=True
    )
    compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug="b", name="B", enabled=False
    )
    all_rows, _ = compliance_service.list_policies(db)
    assert {p.slug for p in all_rows} == {"a", "b"}
    enabled, _ = compliance_service.list_policies(db, enabled_only=True)
    assert {p.slug for p in enabled} == {"a"}


def test_get_policy_by_slug(db, admin_user):
    policy = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug="findme", name="Find Me"
    )
    fetched = compliance_service.get_policy_by_slug(db, "findme")
    assert fetched is not None
    assert fetched.id == policy.id
    assert compliance_service.get_policy_by_slug(db, "missing") is None


def test_update_policy_partial(db, admin_user, capture_audit):
    policy = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug="upd", name="Up"
    )
    initial_version = policy.version
    updated = compliance_service.update_policy(
        db,
        policy.id,
        {"name": "Up Renamed", "severity": "high"},
        actor_user_id=admin_user.id,
    )
    assert updated.name == "Up Renamed"
    assert updated.severity == "high"
    assert updated.version == initial_version + 1
    assert AUDIT_COMPLIANCE_POLICY_UPDATED in capture_audit.actions()


def test_update_policy_disable_emits_disabled_event(db, admin_user, capture_audit):
    policy = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug="onoff", name="OnOff"
    )
    compliance_service.update_policy(
        db,
        policy.id,
        {"enabled": False},
        actor_user_id=admin_user.id,
    )
    assert AUDIT_COMPLIANCE_POLICY_DISABLED in capture_audit.actions()
    compliance_service.update_policy(
        db,
        policy.id,
        {"enabled": True},
        actor_user_id=admin_user.id,
    )
    assert AUDIT_COMPLIANCE_POLICY_ENABLED in capture_audit.actions()


def test_set_policy_enabled_is_idempotent(db, admin_user, capture_audit):
    policy = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug="idem", name="Idem"
    )
    # Already enabled — no new audit row, no version bump.
    before_version = policy.version
    compliance_service.set_policy_enabled(
        db, policy.id, True, actor_user_id=admin_user.id
    )
    db.refresh(policy)
    assert policy.version == before_version
    assert AUDIT_COMPLIANCE_POLICY_ENABLED not in capture_audit.actions()

    compliance_service.set_policy_enabled(
        db, policy.id, False, actor_user_id=admin_user.id
    )
    db.refresh(policy)
    assert policy.enabled is False
    assert policy.version == before_version + 1
    assert AUDIT_COMPLIANCE_POLICY_DISABLED in capture_audit.actions()


def test_update_policy_rejects_unknown_field(db, admin_user):
    policy = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug="unk", name="Unk"
    )
    with pytest.raises(ComplianceError):
        compliance_service.update_policy(
            db,
            policy.id,
            {"slug": "rename-not-allowed"},
            actor_user_id=admin_user.id,
        )


def test_update_policy_not_found(db, admin_user):
    with pytest.raises(ComplianceError) as ei:
        compliance_service.update_policy(
            db,
            999_999,
            {"name": "x"},
            actor_user_id=admin_user.id,
        )
    assert "not found" in str(ei.value)


def test_delete_policy_emits_audit(db, admin_user, capture_audit):
    policy = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug="del", name="Del"
    )
    compliance_service.delete_policy(db, policy.id, actor_user_id=admin_user.id)
    assert (
        db.query(CompliancePolicy).filter(CompliancePolicy.id == policy.id).first()
        is None
    )
    assert AUDIT_COMPLIANCE_POLICY_DELETED in capture_audit.actions()


def test_delete_built_in_is_refused(db, admin_user):
    """Starter-pack rows (built_in=True) must not be deletable;
    operators may disable instead.
    """
    seed = compliance_service.seed_starter_pack(db, actor_user_id=admin_user.id)
    assert seed["seeded"], "starter pack should have seeded entries"
    policy = compliance_service.get_policy_by_slug(db, STARTER_PACK[0]["slug"])
    assert policy is not None and policy.built_in
    with pytest.raises(ComplianceError) as ei:
        compliance_service.delete_policy(db, policy.id, actor_user_id=admin_user.id)
    assert "built-in" in str(ei.value)


# ---------------------------------------------------------------------------
# Check CRUD + kind validation
# ---------------------------------------------------------------------------


def _make_policy(db, admin_user, slug="p1"):
    return compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug.upper(),
    )


def test_add_check_package_installed(db, admin_user, capture_audit):
    policy = _make_policy(db, admin_user)
    check = compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="openssh-installed",
        title="OpenSSH server installed",
        kind="package_installed",
        definition={"package": "openssh-server"},
    )
    assert check.id is not None
    assert check.kind == "package_installed"
    assert check.definition_json == {"package": "openssh-server"}
    assert AUDIT_COMPLIANCE_CHECK_CREATED in capture_audit.actions()
    # Policy version should bump on check add.
    db.refresh(policy)
    assert policy.version == 2


def test_add_check_unknown_kind_rejected(db, admin_user):
    policy = _make_policy(db, admin_user)
    with pytest.raises(ComplianceError) as ei:
        compliance_service.add_check(
            db,
            policy.id,
            actor_user_id=admin_user.id,
            slug="bad",
            title="Bad",
            kind="opencap_xccdf_scan",  # not in vocabulary; OpenSCAP is OUT
            definition={},
        )
    assert "unknown check kind" in str(ei.value)


def test_add_check_rejects_bad_definition_shape(db, admin_user):
    policy = _make_policy(db, admin_user)
    with pytest.raises(ComplianceError):
        compliance_service.add_check(
            db,
            policy.id,
            actor_user_id=admin_user.id,
            slug="bad-pkg",
            title="Bad pkg",
            kind="package_installed",
            definition={"package": "Bad Name With Spaces"},
        )


def test_add_check_rejects_extra_definition_keys(db, admin_user):
    policy = _make_policy(db, admin_user)
    with pytest.raises(ComplianceError) as ei:
        compliance_service.add_check(
            db,
            policy.id,
            actor_user_id=admin_user.id,
            slug="extra-keys",
            title="Extra keys",
            kind="package_installed",
            definition={"package": "openssh-server", "extra": "field"},
        )
    assert "unsupported definition keys" in str(ei.value)


def test_add_check_fact_equals_rejects_bool_expected(db, admin_user):
    policy = _make_policy(db, admin_user)
    with pytest.raises(ComplianceError):
        compliance_service.add_check(
            db,
            policy.id,
            actor_user_id=admin_user.id,
            slug="boolfact",
            title="Bool Fact",
            kind="fact_equals",
            definition={"fact_key": "kernel.x", "expected": True},
        )


def test_add_check_file_sha256_rejects_bad_hex(db, admin_user):
    policy = _make_policy(db, admin_user)
    with pytest.raises(ComplianceError):
        compliance_service.add_check(
            db,
            policy.id,
            actor_user_id=admin_user.id,
            slug="badsha",
            title="Bad SHA",
            kind="file_sha256",
            definition={"path": "/etc/sudoers", "sha256": "deadbeef"},
        )


def test_add_check_command_exit_code_validates_range(db, admin_user):
    policy = _make_policy(db, admin_user)
    with pytest.raises(ComplianceError):
        compliance_service.add_check(
            db,
            policy.id,
            actor_user_id=admin_user.id,
            slug="badcode",
            title="Bad Exit",
            kind="command_exit_code",
            definition={"command": "/bin/true", "expected_exit_code": 300},
        )


def test_add_check_duplicate_slug_rejected(db, admin_user):
    policy = _make_policy(db, admin_user)
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="same",
        title="One",
        kind="package_installed",
        definition={"package": "openssh-server"},
    )
    with pytest.raises(ComplianceError):
        compliance_service.add_check(
            db,
            policy.id,
            actor_user_id=admin_user.id,
            slug="same",
            title="Two",
            kind="package_absent",
            definition={"package": "telnet"},
        )


def test_update_check_partial(db, admin_user, capture_audit):
    policy = _make_policy(db, admin_user)
    check = compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="c1",
        title="C1",
        kind="package_installed",
        definition={"package": "openssh-server"},
    )
    updated = compliance_service.update_check(
        db,
        check.id,
        {
            "title": "C1 Renamed",
            "definition": {"package": "auditd"},
            "enabled": False,
        },
        actor_user_id=admin_user.id,
    )
    assert updated.title == "C1 Renamed"
    assert updated.definition_json == {"package": "auditd"}
    assert updated.enabled is False
    assert AUDIT_COMPLIANCE_CHECK_UPDATED in capture_audit.actions()


def test_update_check_kind_is_immutable(db, admin_user):
    policy = _make_policy(db, admin_user)
    check = compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="c1",
        title="C1",
        kind="package_installed",
        definition={"package": "openssh-server"},
    )
    with pytest.raises(ComplianceError):
        compliance_service.update_check(
            db,
            check.id,
            {"kind": "fact_equals"},
            actor_user_id=admin_user.id,
        )


def test_delete_check_emits_audit_and_cascades(db, admin_user, capture_audit):
    policy = _make_policy(db, admin_user)
    check = compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="c1",
        title="C1",
        kind="package_installed",
        definition={"package": "openssh-server"},
    )
    compliance_service.delete_check(db, check.id, actor_user_id=admin_user.id)
    assert (
        db.query(CompliancePolicyCheck)
        .filter(CompliancePolicyCheck.id == check.id)
        .first()
        is None
    )
    assert AUDIT_COMPLIANCE_CHECK_DELETED in capture_audit.actions()


def test_list_checks_orders_by_display_then_slug(db, admin_user):
    policy = _make_policy(db, admin_user)
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="b",
        title="B",
        kind="package_installed",
        definition={"package": "openssh-server"},
        display_order=10,
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="a",
        title="A",
        kind="package_installed",
        definition={"package": "auditd"},
        display_order=10,
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="z",
        title="Z",
        kind="package_absent",
        definition={"package": "telnet"},
        display_order=1,
    )
    rows = compliance_service.list_checks(db, policy.id)
    assert [c.slug for c in rows] == ["z", "a", "b"]


# ---------------------------------------------------------------------------
# Read envelopes — Slice 1 must explicitly surface runner status
# ---------------------------------------------------------------------------


def test_check_read_envelope_marks_package_kinds_as_slice2(db, admin_user):
    policy = _make_policy(db, admin_user)
    check = compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="c",
        title="C",
        kind="package_installed",
        definition={"package": "openssh-server"},
    )
    env = compliance_service.check_read_envelope(check)
    assert env["runner_status"] == RUNNER_STATUS_NOT_IMPLEMENTED
    assert env["runner_owner"] == RUNNER_OWNER_SLICE_2
    # Absolute-UTC ISO with 'Z' suffix (Slice 1 read-wire lock).
    assert isinstance(env["created_at"], str) and env["created_at"].endswith("Z")
    assert isinstance(env["updated_at"], str) and env["updated_at"].endswith("Z")


def test_policy_read_envelope_timestamps_end_in_z(db, admin_user):
    policy = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug="ts", name="TS"
    )
    env = compliance_service.policy_read_envelope(policy)
    assert isinstance(env["created_at"], str) and env["created_at"].endswith("Z")
    assert isinstance(env["updated_at"], str) and env["updated_at"].endswith("Z")


def test_check_read_envelope_marks_file_kinds_as_pra166(db, admin_user):
    policy = _make_policy(db, admin_user)
    check = compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="cf",
        title="CF",
        kind="file_exists",
        definition={"path": "/etc/sudoers"},
    )
    env = compliance_service.check_read_envelope(check)
    assert env["runner_status"] == RUNNER_STATUS_NOT_IMPLEMENTED
    assert env["runner_owner"] == RUNNER_OWNER_PRA166


def test_all_kinds_have_runner_owner(db, admin_user):
    """Every kind in the vocabulary must have an explicit runner owner.
    This guards against accidentally-runnable kinds slipping into the
    vocabulary without a deferral marker.
    """
    for kind, meta in KNOWN_CHECK_KINDS.items():
        assert meta["runner_owner"] in {
            RUNNER_OWNER_SLICE_2,
            RUNNER_OWNER_PRA166,
        }, kind


# ---------------------------------------------------------------------------
# Starter pack — idempotency + audit
# ---------------------------------------------------------------------------


def test_seed_starter_pack_first_run(db, admin_user, capture_audit):
    result = compliance_service.seed_starter_pack(db, actor_user_id=admin_user.id)
    expected_keys = [e["starter_pack_key"] for e in STARTER_PACK]
    assert sorted(result["seeded"]) == sorted(expected_keys)
    assert result["skipped"] == []
    assert db.query(CompliancePolicy).filter(
        CompliancePolicy.built_in.is_(True)
    ).count() == len(STARTER_PACK)
    # Audit: one seeded event per inserted policy.
    seeded_events = capture_audit.by_action(AUDIT_COMPLIANCE_STARTER_PACK_SEEDED)
    assert len(seeded_events) == len(STARTER_PACK)


def test_seed_starter_pack_is_idempotent(db, admin_user, capture_audit):
    """Re-running the seed must not duplicate rows, must not bump
    counts, must not emit new audit events.
    """
    compliance_service.seed_starter_pack(db, actor_user_id=admin_user.id)
    first_count = db.query(CompliancePolicy).count()
    first_check_count = db.query(CompliancePolicyCheck).count()

    capture_audit.calls.clear()
    result = compliance_service.seed_starter_pack(db, actor_user_id=admin_user.id)
    assert result["seeded"] == []
    assert sorted(result["skipped"]) == sorted(
        [e["starter_pack_key"] for e in STARTER_PACK]
    )
    assert db.query(CompliancePolicy).count() == first_count
    assert db.query(CompliancePolicyCheck).count() == first_check_count
    assert capture_audit.by_action(AUDIT_COMPLIANCE_STARTER_PACK_SEEDED) == []


def test_seed_starter_pack_leaves_operator_edits_alone(db, admin_user):
    """If an operator disabled or renamed a seeded row, re-running the
    seeder must NOT clobber that operator state.
    """
    compliance_service.seed_starter_pack(db, actor_user_id=admin_user.id)
    target_slug = STARTER_PACK[0]["slug"]
    policy = compliance_service.get_policy_by_slug(db, target_slug)
    assert policy is not None
    compliance_service.update_policy(
        db,
        policy.id,
        {"name": "Operator Renamed", "enabled": False},
        actor_user_id=admin_user.id,
    )

    result = compliance_service.seed_starter_pack(db, actor_user_id=admin_user.id)
    assert result["seeded"] == []
    refreshed = compliance_service.get_policy_by_slug(db, target_slug)
    assert refreshed is not None
    assert refreshed.name == "Operator Renamed"
    assert refreshed.enabled is False


def test_starter_pack_preview_shape():
    preview = compliance_service.starter_pack_preview()
    assert preview, "starter pack must not be empty"
    for entry in preview:
        assert "starter_pack_key" in entry
        assert "slug" in entry
        assert "check_count" in entry
        assert entry["check_count"] >= 1
        # Runner owners are explicit on the preview so the UI can
        # show "won't execute in Slice 1" before seeding.
        assert entry["runner_owners"], entry["starter_pack_key"]
        for owner in entry["runner_owners"]:
            assert owner in {RUNNER_OWNER_SLICE_2, RUNNER_OWNER_PRA166}


# ---------------------------------------------------------------------------
# Non-execution guard
# ---------------------------------------------------------------------------


def test_no_probe_runner_module_imported_by_service():
    """Slice 1 hard boundary — the compliance service must not import
    any probe runner module. If a future slice adds one, this test
    must fail until the module list explicitly opts in.
    """
    import app.services.compliance_service as svc  # noqa: WPS433

    forbidden = {
        "ssh_facts_collector_service",
        "ssh_service",
        "facts_service",
        "package_service",
        "patch_advisory_service",
        "patch_execution_service",
    }
    imported = {name.split(".")[-1] for name in dir(svc) if not name.startswith("_")}
    # The module re-exports a handful of helpers; assert none are the
    # runner modules above. (compliance_starter_pack is allowed.)
    leaks = imported & forbidden
    assert not leaks, f"compliance_service leaked runner imports: {leaks}"


def test_no_facts_or_package_runner_call_in_seed(
    db, admin_user, monkeypatch, capture_audit
):
    """Seeding must not invoke ``facts_service`` or ``package_service``
    — Slice 1 stores metadata only.
    """
    sentinels = {}

    def trip_facts(*args, **kwargs):
        sentinels["facts"] = True
        raise AssertionError("facts_service must not run in Slice 1 seed")

    def trip_packages(*args, **kwargs):
        sentinels["packages"] = True
        raise AssertionError("package_service must not run in Slice 1 seed")

    # FactsService.ingest is a module-level function in facts_service;
    # PackageService.scan_packages is an instance method on the class.
    monkeypatch.setattr(
        "app.services.facts_service.ingest",
        trip_facts,
        raising=False,
    )
    monkeypatch.setattr(
        "app.services.package_service.PackageService.scan_packages",
        trip_packages,
        raising=False,
    )
    compliance_service.seed_starter_pack(db, actor_user_id=admin_user.id)
    assert "facts" not in sentinels
    assert "packages" not in sentinels
