"""PRA-162 slice 4 — gate definition / signal / promotion-readiness service tests.

Covers:
* Gate CRUD with vocabulary CHECKs (gate_kind, comparator).
* Cross-field validation: threshold gates require comparator + numeric threshold.
* Signal record/list/delete + audit shape (safe_emit no db=).
* Latest-non-expired signal selection per (ring, signal_key).
* Expired signals do not satisfy a gate.
* Promotion readiness vocabulary: ring_disabled / blocked / missing_signal /
  no_gates / ready (priority ring_disabled > blocked > missing_signal >
  no_gates > ready).
* Optional gates report state but never block readiness.
* Disabled gates are ignored during evaluation.
* Boolean and threshold gate evaluation correctness.
* DB-level FK behavior: ring CASCADE drops gate defs + signals; gate
  def deletion SET NULLs the signal FK (signal rows survive).
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.models import PatchRingGateDefinition, PatchRingGateSignal
from app.services import patch_ring_service
from app.services.patch_ring_service import (
    AUDIT_PATCH_RING_GATE_CREATED,
    AUDIT_PATCH_RING_GATE_DELETED,
    AUDIT_PATCH_RING_GATE_SIGNAL_DELETED,
    AUDIT_PATCH_RING_GATE_SIGNAL_RECORDED,
    GATE_DETAIL_DISABLED,
    GATE_DETAIL_EXPIRED,
    GATE_DETAIL_FAILING,
    GATE_DETAIL_IGNORED_OPTIONAL,
    GATE_DETAIL_MISSING,
    GATE_DETAIL_SATISFIED,
    PROMOTION_BLOCKED,
    PROMOTION_MISSING_SIGNAL,
    PROMOTION_NO_GATES,
    PROMOTION_READY,
    PROMOTION_RING_DISABLED,
    PatchRingError,
)

# -- Helpers ---------------------------------------------------------------


def _make_ring(db, admin_user, slug, *, sort_order, enabled=True):
    return patch_ring_service.create_ring(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        sort_order=sort_order,
        enabled=enabled,
    )


def _make_bool_gate(db, admin_user, ring, *, signal_key, required=True, enabled=True):
    return patch_ring_service.create_gate(
        db,
        ring.id,
        actor_user_id=admin_user.id,
        signal_key=signal_key,
        name=signal_key,
        gate_kind="boolean",
        required=required,
        enabled=enabled,
    )


def _record_pass(db, admin_user, ring, *, signal_key, value=True, **kw):
    return patch_ring_service.record_gate_signal(
        db,
        ring.id,
        actor_user_id=admin_user.id,
        signal_key=signal_key,
        status="pass",
        value=value,
        **kw,
    )


def _record_fail(db, admin_user, ring, *, signal_key, **kw):
    return patch_ring_service.record_gate_signal(
        db,
        ring.id,
        actor_user_id=admin_user.id,
        signal_key=signal_key,
        status="fail",
        **kw,
    )


# -- Gate CRUD -------------------------------------------------------------


def test_create_boolean_gate(db, admin_user):
    ring = _make_ring(db, admin_user, "g-bool", sort_order=1)
    gate = _make_bool_gate(db, admin_user, ring, signal_key="smoke.ok")
    assert gate.id is not None
    assert gate.signal_key == "smoke.ok"
    assert gate.gate_kind == "boolean"
    assert gate.comparator is None  # boolean ignores comparator
    assert gate.enabled is True
    assert gate.required is True


def test_create_threshold_gate_requires_comparator(db, admin_user):
    ring = _make_ring(db, admin_user, "g-th-no-comp", sort_order=1)
    with pytest.raises(PatchRingError) as exc:
        patch_ring_service.create_gate(
            db,
            ring.id,
            actor_user_id=admin_user.id,
            signal_key="errors.below",
            name="errors below",
            gate_kind="threshold",
            parameters={"threshold": 5},
        )
    assert "require a comparator" in str(exc.value)


def test_create_threshold_gate_requires_numeric_threshold(db, admin_user):
    ring = _make_ring(db, admin_user, "g-th-bad-thr", sort_order=1)
    with pytest.raises(PatchRingError) as exc:
        patch_ring_service.create_gate(
            db,
            ring.id,
            actor_user_id=admin_user.id,
            signal_key="errors.below",
            name="errors below",
            gate_kind="threshold",
            comparator="lte",
            parameters={"threshold": "not-a-number"},
        )
    assert "must be numeric" in str(exc.value)


def test_create_gate_rejects_bad_kind(db, admin_user):
    ring = _make_ring(db, admin_user, "g-bad-kind", sort_order=1)
    with pytest.raises(PatchRingError) as exc:
        patch_ring_service.create_gate(
            db,
            ring.id,
            actor_user_id=admin_user.id,
            signal_key="any",
            name="any",
            gate_kind="probe",  # not in vocab
        )
    assert "gate_kind" in str(exc.value)


def test_create_gate_duplicate_signal_key_rejected(db, admin_user):
    ring = _make_ring(db, admin_user, "g-dup", sort_order=1)
    _make_bool_gate(db, admin_user, ring, signal_key="dup")
    with pytest.raises(PatchRingError) as exc:
        _make_bool_gate(db, admin_user, ring, signal_key="dup")
    assert "already has a gate" in str(exc.value)


def test_create_gate_emits_audit(db, admin_user, monkeypatch):
    ring = _make_ring(db, admin_user, "g-audit", sort_order=1)
    captured = {}

    def fake_safe_emit(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(patch_ring_service, "safe_emit", fake_safe_emit)
    patch_ring_service.create_gate(
        db,
        ring.id,
        actor_user_id=admin_user.id,
        actor_username="admin",
        signal_key="audit.gate",
        name="Audit Gate",
        gate_kind="boolean",
    )
    assert captured["action"] == AUDIT_PATCH_RING_GATE_CREATED
    assert captured["context"]["signal_key"] == "audit.gate"
    assert "db" not in captured  # session boundary rule


def test_update_gate_idempotent_no_audit_on_no_change(db, admin_user, monkeypatch):
    ring = _make_ring(db, admin_user, "g-idem", sort_order=1)
    gate = _make_bool_gate(db, admin_user, ring, signal_key="idem")

    captured = []

    def fake_safe_emit(**kwargs):
        captured.append(kwargs)

    monkeypatch.setattr(patch_ring_service, "safe_emit", fake_safe_emit)
    patch_ring_service.update_gate(
        db, ring.id, gate.id, {"required": True}, actor_user_id=admin_user.id
    )
    assert captured == []


def test_update_gate_signal_key_immutable(db, admin_user):
    ring = _make_ring(db, admin_user, "g-imm", sort_order=1)
    gate = _make_bool_gate(db, admin_user, ring, signal_key="locked")
    with pytest.raises(PatchRingError) as exc:
        patch_ring_service.update_gate(
            db,
            ring.id,
            gate.id,
            {"signal_key": "renamed"},
            actor_user_id=admin_user.id,
        )
    assert "immutable" in str(exc.value)


def test_update_gate_can_disable(db, admin_user):
    ring = _make_ring(db, admin_user, "g-disable", sort_order=1)
    gate = _make_bool_gate(db, admin_user, ring, signal_key="off")
    updated = patch_ring_service.update_gate(
        db, ring.id, gate.id, {"enabled": False}, actor_user_id=admin_user.id
    )
    assert updated.enabled is False


def test_delete_gate_removes_row_and_audits(db, admin_user, monkeypatch):
    ring = _make_ring(db, admin_user, "g-del", sort_order=1)
    gate = _make_bool_gate(db, admin_user, ring, signal_key="del")

    captured = {}

    def fake_safe_emit(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(patch_ring_service, "safe_emit", fake_safe_emit)
    patch_ring_service.delete_gate(db, ring.id, gate.id, actor_user_id=admin_user.id)
    assert captured["action"] == AUDIT_PATCH_RING_GATE_DELETED
    remaining = patch_ring_service.list_gates(db, ring.id)
    assert remaining == []


def test_list_gates_unknown_ring_404_wording(db):
    with pytest.raises(PatchRingError) as exc:
        patch_ring_service.list_gates(db, 999_999)
    assert "not found" in str(exc.value)


# -- Signal record/list/delete --------------------------------------------


def test_record_signal_links_gate_definition_when_matching(db, admin_user):
    ring = _make_ring(db, admin_user, "s-link", sort_order=1)
    gate = _make_bool_gate(db, admin_user, ring, signal_key="probe.ok")
    signal = _record_pass(db, admin_user, ring, signal_key="probe.ok")
    assert signal.gate_definition_id == gate.id


def test_record_signal_without_matching_definition_allowed(db, admin_user):
    """Operators may record evidence ahead of declaring the gate; PRA-171/172
    writers may also record signals without a 1:1 definition."""
    ring = _make_ring(db, admin_user, "s-orphan", sort_order=1)
    signal = _record_pass(db, admin_user, ring, signal_key="future.gate")
    assert signal.gate_definition_id is None


def test_record_signal_audit_shape(db, admin_user, monkeypatch):
    ring = _make_ring(db, admin_user, "s-audit", sort_order=1)
    captured = {}

    def fake_safe_emit(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(patch_ring_service, "safe_emit", fake_safe_emit)
    _record_pass(db, admin_user, ring, signal_key="audit.signal")
    assert captured["action"] == AUDIT_PATCH_RING_GATE_SIGNAL_RECORDED
    assert "db" not in captured


def test_record_signal_rejects_bad_status(db, admin_user):
    ring = _make_ring(db, admin_user, "s-bad-status", sort_order=1)
    with pytest.raises(PatchRingError):
        patch_ring_service.record_gate_signal(
            db,
            ring.id,
            actor_user_id=admin_user.id,
            signal_key="any",
            status="unknown",  # not in vocab
        )


def test_record_signal_rejects_bad_source_kind(db, admin_user):
    ring = _make_ring(db, admin_user, "s-bad-source", sort_order=1)
    with pytest.raises(PatchRingError):
        patch_ring_service.record_gate_signal(
            db,
            ring.id,
            actor_user_id=admin_user.id,
            signal_key="any",
            status="pass",
            source_kind="hand-wave",  # not in vocab
        )


def test_list_signals_orders_latest_first(db, admin_user):
    ring = _make_ring(db, admin_user, "s-order", sort_order=1)
    older = _record_pass(
        db,
        admin_user,
        ring,
        signal_key="order",
        observed_at=datetime.utcnow() - timedelta(hours=2),
    )
    newer = _record_pass(
        db,
        admin_user,
        ring,
        signal_key="order",
        observed_at=datetime.utcnow(),
    )
    rows = patch_ring_service.list_gate_signals(db, ring.id)
    assert [r.id for r in rows[:2]] == [newer.id, older.id]


def test_delete_signal_404_not_on_ring(db, admin_user):
    ring = _make_ring(db, admin_user, "s-del", sort_order=1)
    other = _make_ring(db, admin_user, "s-del-other", sort_order=2)
    signal = _record_pass(db, admin_user, ring, signal_key="x")
    with pytest.raises(PatchRingError) as exc:
        patch_ring_service.delete_gate_signal(
            db, other.id, signal.id, actor_user_id=admin_user.id
        )
    assert "not found" in str(exc.value)


def test_delete_signal_emits_audit(db, admin_user, monkeypatch):
    ring = _make_ring(db, admin_user, "s-del-audit", sort_order=1)
    signal = _record_pass(db, admin_user, ring, signal_key="x")

    captured = {}

    def fake_safe_emit(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(patch_ring_service, "safe_emit", fake_safe_emit)
    patch_ring_service.delete_gate_signal(
        db, ring.id, signal.id, actor_user_id=admin_user.id
    )
    assert captured["action"] == AUDIT_PATCH_RING_GATE_SIGNAL_DELETED


# -- Latest-signal + expiry semantics -------------------------------------


def test_latest_signal_wins_for_evaluation(db, admin_user):
    ring = _make_ring(db, admin_user, "lat", sort_order=1)
    _make_bool_gate(db, admin_user, ring, signal_key="lat.gate")
    _record_fail(
        db,
        admin_user,
        ring,
        signal_key="lat.gate",
        observed_at=datetime.utcnow() - timedelta(hours=1),
    )
    _record_pass(db, admin_user, ring, signal_key="lat.gate")
    res = patch_ring_service.evaluate_promotion_readiness(db, ring.id)
    assert res["status"] == PROMOTION_READY


def test_expired_signal_treated_as_missing_for_required_gate(db, admin_user):
    ring = _make_ring(db, admin_user, "exp", sort_order=1)
    _make_bool_gate(db, admin_user, ring, signal_key="exp.gate")
    _record_pass(
        db,
        admin_user,
        ring,
        signal_key="exp.gate",
        expires_at=datetime.utcnow() - timedelta(seconds=1),
    )
    res = patch_ring_service.evaluate_promotion_readiness(db, ring.id)
    assert res["status"] == PROMOTION_MISSING_SIGNAL
    assert res["gates"][0]["gate_status"] == GATE_DETAIL_EXPIRED


def test_unexpired_signal_satisfies_gate(db, admin_user):
    ring = _make_ring(db, admin_user, "unx", sort_order=1)
    _make_bool_gate(db, admin_user, ring, signal_key="unx.gate")
    _record_pass(
        db,
        admin_user,
        ring,
        signal_key="unx.gate",
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    res = patch_ring_service.evaluate_promotion_readiness(db, ring.id)
    assert res["status"] == PROMOTION_READY


# -- Promotion readiness verdicts -----------------------------------------


def test_promotion_readiness_disabled_ring(db, admin_user):
    ring = _make_ring(db, admin_user, "pr-off", sort_order=1, enabled=False)
    res = patch_ring_service.evaluate_promotion_readiness(db, ring.id)
    assert res["status"] == PROMOTION_RING_DISABLED
    assert res["ring_enabled"] is False
    assert res["gates"] == []


def test_promotion_readiness_no_gates(db, admin_user):
    ring = _make_ring(db, admin_user, "pr-empty", sort_order=1)
    res = patch_ring_service.evaluate_promotion_readiness(db, ring.id)
    assert res["status"] == PROMOTION_NO_GATES


def test_promotion_readiness_only_disabled_gates_is_no_gates(db, admin_user):
    ring = _make_ring(db, admin_user, "pr-disabled-gates", sort_order=1)
    _make_bool_gate(db, admin_user, ring, signal_key="off.gate", enabled=False)
    res = patch_ring_service.evaluate_promotion_readiness(db, ring.id)
    assert res["status"] == PROMOTION_NO_GATES
    # Disabled gates are still surfaced in the per-gate list.
    assert len(res["gates"]) == 1
    assert res["gates"][0]["gate_status"] == GATE_DETAIL_DISABLED


def test_promotion_readiness_missing_signal(db, admin_user):
    ring = _make_ring(db, admin_user, "pr-miss", sort_order=1)
    _make_bool_gate(db, admin_user, ring, signal_key="needed")
    res = patch_ring_service.evaluate_promotion_readiness(db, ring.id)
    assert res["status"] == PROMOTION_MISSING_SIGNAL
    assert res["gates"][0]["gate_status"] == GATE_DETAIL_MISSING


def test_promotion_readiness_blocked_beats_missing(db, admin_user):
    ring = _make_ring(db, admin_user, "pr-mix", sort_order=1)
    _make_bool_gate(db, admin_user, ring, signal_key="a")
    _make_bool_gate(db, admin_user, ring, signal_key="b")
    _record_fail(db, admin_user, ring, signal_key="a")
    # b has no signal at all
    res = patch_ring_service.evaluate_promotion_readiness(db, ring.id)
    assert res["status"] == PROMOTION_BLOCKED


def test_promotion_readiness_ready_when_all_required_pass(db, admin_user):
    ring = _make_ring(db, admin_user, "pr-go", sort_order=1)
    _make_bool_gate(db, admin_user, ring, signal_key="alpha")
    _make_bool_gate(db, admin_user, ring, signal_key="beta")
    _record_pass(db, admin_user, ring, signal_key="alpha")
    _record_pass(db, admin_user, ring, signal_key="beta")
    res = patch_ring_service.evaluate_promotion_readiness(db, ring.id)
    assert res["status"] == PROMOTION_READY
    assert all(g["gate_status"] == GATE_DETAIL_SATISFIED for g in res["gates"])


def test_promotion_readiness_optional_gate_does_not_block(db, admin_user):
    ring = _make_ring(db, admin_user, "pr-opt", sort_order=1)
    _make_bool_gate(db, admin_user, ring, signal_key="req")
    _make_bool_gate(db, admin_user, ring, signal_key="opt", required=False)
    _record_pass(db, admin_user, ring, signal_key="req")
    # Optional gate is missing — must not block
    res = patch_ring_service.evaluate_promotion_readiness(db, ring.id)
    assert res["status"] == PROMOTION_READY
    opt_detail = next(g for g in res["gates"] if g["signal_key"] == "opt")
    assert opt_detail["gate_status"] == GATE_DETAIL_IGNORED_OPTIONAL


def test_promotion_readiness_optional_failing_signal_still_ready(db, admin_user):
    ring = _make_ring(db, admin_user, "pr-opt-fail", sort_order=1)
    _make_bool_gate(db, admin_user, ring, signal_key="req")
    _make_bool_gate(db, admin_user, ring, signal_key="opt", required=False)
    _record_pass(db, admin_user, ring, signal_key="req")
    _record_fail(db, admin_user, ring, signal_key="opt")
    res = patch_ring_service.evaluate_promotion_readiness(db, ring.id)
    assert res["status"] == PROMOTION_READY
    opt_detail = next(g for g in res["gates"] if g["signal_key"] == "opt")
    assert opt_detail["gate_status"] == GATE_DETAIL_IGNORED_OPTIONAL


# -- Boolean + threshold evaluation ---------------------------------------


def test_boolean_gate_with_explicit_expected_false(db, admin_user):
    ring = _make_ring(db, admin_user, "bool-false", sort_order=1)
    patch_ring_service.create_gate(
        db,
        ring.id,
        actor_user_id=admin_user.id,
        signal_key="critical.absent",
        name="no-criticals",
        gate_kind="boolean",
        parameters={"expected": False},
    )
    _record_pass(db, admin_user, ring, signal_key="critical.absent", value=False)
    res = patch_ring_service.evaluate_promotion_readiness(db, ring.id)
    assert res["status"] == PROMOTION_READY


def test_boolean_gate_value_mismatches_expected_blocks(db, admin_user):
    ring = _make_ring(db, admin_user, "bool-mismatch", sort_order=1)
    _make_bool_gate(db, admin_user, ring, signal_key="ok")
    _record_pass(db, admin_user, ring, signal_key="ok", value=False)
    res = patch_ring_service.evaluate_promotion_readiness(db, ring.id)
    assert res["status"] == PROMOTION_BLOCKED
    assert res["gates"][0]["gate_status"] == GATE_DETAIL_FAILING


@pytest.mark.parametrize(
    "comparator,threshold,value,expected_ready",
    [
        ("gte", 5, 5, True),
        ("gte", 5, 4, False),
        ("gt", 5, 6, True),
        ("gt", 5, 5, False),
        ("lte", 5, 5, True),
        ("lt", 5, 5, False),
        ("eq", 5, 5, True),
        ("eq", 5, 6, False),
        ("ne", 5, 6, True),
        ("ne", 5, 5, False),
    ],
)
def test_threshold_gate_comparators(
    db, admin_user, comparator, threshold, value, expected_ready
):
    ring = _make_ring(
        db, admin_user, f"th-{comparator}-{threshold}-{value}", sort_order=1
    )
    patch_ring_service.create_gate(
        db,
        ring.id,
        actor_user_id=admin_user.id,
        signal_key="metric",
        name="metric",
        gate_kind="threshold",
        comparator=comparator,
        parameters={"threshold": threshold},
    )
    _record_pass(db, admin_user, ring, signal_key="metric", value=value)
    res = patch_ring_service.evaluate_promotion_readiness(db, ring.id)
    if expected_ready:
        assert res["status"] == PROMOTION_READY
    else:
        assert res["status"] == PROMOTION_BLOCKED


def test_fail_status_signal_never_satisfies_even_with_passing_value(db, admin_user):
    ring = _make_ring(db, admin_user, "th-fail", sort_order=1)
    patch_ring_service.create_gate(
        db,
        ring.id,
        actor_user_id=admin_user.id,
        signal_key="m",
        name="m",
        gate_kind="threshold",
        comparator="gte",
        parameters={"threshold": 5},
    )
    _record_fail(
        db, admin_user, ring, signal_key="m", value=10
    )  # value passes, status doesn't
    res = patch_ring_service.evaluate_promotion_readiness(db, ring.id)
    assert res["status"] == PROMOTION_BLOCKED


# -- DB-level FK behavior -------------------------------------------------


def test_ring_delete_cascades_gate_definitions(db, admin_user):
    ring = _make_ring(db, admin_user, "cas-gate", sort_order=1)
    _make_bool_gate(db, admin_user, ring, signal_key="x")
    patch_ring_service.delete_ring(db, ring.id, actor_user_id=admin_user.id)
    assert (
        db.query(PatchRingGateDefinition)
        .filter(PatchRingGateDefinition.ring_id == ring.id)
        .count()
        == 0
    )


def test_ring_delete_cascades_gate_signals(db, admin_user):
    ring = _make_ring(db, admin_user, "cas-sig", sort_order=1)
    _record_pass(db, admin_user, ring, signal_key="x")
    patch_ring_service.delete_ring(db, ring.id, actor_user_id=admin_user.id)
    assert (
        db.query(PatchRingGateSignal)
        .filter(PatchRingGateSignal.ring_id == ring.id)
        .count()
        == 0
    )


def test_gate_delete_set_nulls_signal_fk(db, admin_user):
    """Historical signals must survive a definition removal so the audit
    trail stays intact; FK is ``ON DELETE SET NULL`` for that reason."""
    ring = _make_ring(db, admin_user, "cas-setnull", sort_order=1)
    gate = _make_bool_gate(db, admin_user, ring, signal_key="link")
    signal = _record_pass(db, admin_user, ring, signal_key="link")
    assert signal.gate_definition_id == gate.id

    patch_ring_service.delete_gate(db, ring.id, gate.id, actor_user_id=admin_user.id)
    db.refresh(signal)
    assert signal.id is not None  # signal row survived
    assert signal.gate_definition_id is None  # FK SET NULL fired
