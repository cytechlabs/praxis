"""PRA-162 slice 4 — gate definition / signal / promotion-readiness route tests."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

# -- Helpers ---------------------------------------------------------------


def _create_ring(authed_client, slug, *, sort_order, enabled=True):
    res = authed_client.post(
        "/patch/rings",
        json={
            "slug": slug,
            "name": slug,
            "sort_order": sort_order,
            "enabled": enabled,
        },
    )
    assert res.status_code == 201, res.text
    return res.json()


def _create_bool_gate(
    authed_client, ring_id, *, signal_key, required=True, enabled=True
):
    res = authed_client.post(
        f"/patch/rings/{ring_id}/gates",
        json={
            "signal_key": signal_key,
            "name": signal_key,
            "gate_kind": "boolean",
            "required": required,
            "enabled": enabled,
        },
    )
    assert res.status_code == 201, res.text
    return res.json()


def _record_signal(authed_client, ring_id, *, signal_key, status, **extra):
    res = authed_client.post(
        f"/patch/rings/{ring_id}/gate-signals",
        json={"signal_key": signal_key, "status": status, **extra},
    )
    assert res.status_code == 201, res.text
    return res.json()


# -- Gate CRUD routes -----------------------------------------------------


def test_post_gate_201(authed_client):
    ring = _create_ring(authed_client, "gr-create", sort_order=1)
    res = authed_client.post(
        f"/patch/rings/{ring['id']}/gates",
        json={
            "signal_key": "smoke.ok",
            "name": "Smoke",
            "gate_kind": "boolean",
        },
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["signal_key"] == "smoke.ok"
    assert body["gate_kind"] == "boolean"
    assert body["enabled"] is True


def test_post_threshold_gate_201(authed_client):
    ring = _create_ring(authed_client, "gr-th", sort_order=1)
    res = authed_client.post(
        f"/patch/rings/{ring['id']}/gates",
        json={
            "signal_key": "errors",
            "name": "Errors",
            "gate_kind": "threshold",
            "comparator": "lte",
            "parameters": {"threshold": 5},
        },
    )
    assert res.status_code == 201
    body = res.json()
    assert body["comparator"] == "lte"
    assert body["parameters"] == {"threshold": 5}


def test_post_gate_unknown_ring_404(authed_client):
    res = authed_client.post(
        "/patch/rings/999999/gates",
        json={"signal_key": "x", "name": "X", "gate_kind": "boolean"},
    )
    assert res.status_code == 404


def test_post_gate_bad_kind_422(authed_client):
    ring = _create_ring(authed_client, "gr-bad", sort_order=1)
    res = authed_client.post(
        f"/patch/rings/{ring['id']}/gates",
        json={"signal_key": "x", "name": "X", "gate_kind": "probe"},
    )
    assert res.status_code == 422


def test_post_gate_threshold_without_comparator_422(authed_client):
    ring = _create_ring(authed_client, "gr-th-bad", sort_order=1)
    res = authed_client.post(
        f"/patch/rings/{ring['id']}/gates",
        json={
            "signal_key": "x",
            "name": "X",
            "gate_kind": "threshold",
            "parameters": {"threshold": 5},
        },
    )
    assert res.status_code == 422


def test_post_gate_duplicate_signal_key_422(authed_client):
    ring = _create_ring(authed_client, "gr-dup", sort_order=1)
    _create_bool_gate(authed_client, ring["id"], signal_key="dup")
    res = authed_client.post(
        f"/patch/rings/{ring['id']}/gates",
        json={"signal_key": "dup", "name": "X", "gate_kind": "boolean"},
    )
    assert res.status_code == 422


def test_post_gate_requires_admin_or_maintainer(client, auditor_user, authed_client):
    ring = _create_ring(authed_client, "gr-auth", sort_order=1)
    res = client.post(
        "/auth/login",
        data={"username": auditor_user.username, "password": "testpass123"},
    )
    token = res.json()["access_token"]
    res = client.post(
        f"/patch/rings/{ring['id']}/gates",
        headers={"Authorization": f"Bearer {token}"},
        json={"signal_key": "x", "name": "X", "gate_kind": "boolean"},
    )
    assert res.status_code in (401, 403)


def test_get_gates_orders_by_signal_key(authed_client):
    ring = _create_ring(authed_client, "gr-order", sort_order=1)
    for k in ("z", "a", "m"):
        _create_bool_gate(authed_client, ring["id"], signal_key=k)
    res = authed_client.get(f"/patch/rings/{ring['id']}/gates")
    assert res.status_code == 200
    assert [g["signal_key"] for g in res.json()] == ["a", "m", "z"]


def test_patch_gate_updates_fields(authed_client):
    ring = _create_ring(authed_client, "gr-patch", sort_order=1)
    gate = _create_bool_gate(authed_client, ring["id"], signal_key="p")
    res = authed_client.patch(
        f"/patch/rings/{ring['id']}/gates/{gate['id']}",
        json={"required": False, "description": "optional now"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["required"] is False
    assert body["description"] == "optional now"


def test_patch_gate_signal_key_immutable_422(authed_client):
    ring = _create_ring(authed_client, "gr-imm", sort_order=1)
    gate = _create_bool_gate(authed_client, ring["id"], signal_key="locked")
    res = authed_client.patch(
        f"/patch/rings/{ring['id']}/gates/{gate['id']}",
        json={"signal_key": "renamed"},
    )
    assert res.status_code == 422
    assert "immutable" in res.json()["detail"]


def test_patch_gate_empty_body_422(authed_client):
    ring = _create_ring(authed_client, "gr-empty", sort_order=1)
    gate = _create_bool_gate(authed_client, ring["id"], signal_key="e")
    res = authed_client.patch(f"/patch/rings/{ring['id']}/gates/{gate['id']}", json={})
    assert res.status_code == 422


def test_patch_gate_unknown_id_404(authed_client):
    ring = _create_ring(authed_client, "gr-pun", sort_order=1)
    res = authed_client.patch(
        f"/patch/rings/{ring['id']}/gates/999999", json={"required": False}
    )
    assert res.status_code == 404


def test_delete_gate_204(authed_client):
    ring = _create_ring(authed_client, "gr-del", sort_order=1)
    gate = _create_bool_gate(authed_client, ring["id"], signal_key="d")
    res = authed_client.delete(f"/patch/rings/{ring['id']}/gates/{gate['id']}")
    assert res.status_code == 204


def test_delete_gate_unknown_id_404(authed_client):
    ring = _create_ring(authed_client, "gr-d404", sort_order=1)
    res = authed_client.delete(f"/patch/rings/{ring['id']}/gates/999999")
    assert res.status_code == 404


# -- Gate signal routes ---------------------------------------------------


def test_post_signal_201(authed_client):
    ring = _create_ring(authed_client, "sr-create", sort_order=1)
    res = authed_client.post(
        f"/patch/rings/{ring['id']}/gate-signals",
        json={"signal_key": "x", "status": "pass"},
    )
    assert res.status_code == 201
    body = res.json()
    assert body["status"] == "pass"
    assert body["source_kind"] == "manual"


def test_post_signal_with_value_and_details(authed_client):
    ring = _create_ring(authed_client, "sr-jsonb", sort_order=1)
    res = authed_client.post(
        f"/patch/rings/{ring['id']}/gate-signals",
        json={
            "signal_key": "metric",
            "status": "pass",
            "value": 42,
            "details": {"reviewer": "ops-oncall", "notes": "ok"},
        },
    )
    assert res.status_code == 201
    body = res.json()
    assert body["value"] == 42
    assert body["details"]["reviewer"] == "ops-oncall"


def test_post_signal_unknown_ring_404(authed_client):
    res = authed_client.post(
        "/patch/rings/999999/gate-signals",
        json={"signal_key": "x", "status": "pass"},
    )
    assert res.status_code == 404


def test_post_signal_bad_status_422(authed_client):
    ring = _create_ring(authed_client, "sr-bad", sort_order=1)
    res = authed_client.post(
        f"/patch/rings/{ring['id']}/gate-signals",
        json={"signal_key": "x", "status": "unknown"},
    )
    assert res.status_code == 422


def test_post_signal_bad_source_kind_422(authed_client):
    ring = _create_ring(authed_client, "sr-bad-src", sort_order=1)
    res = authed_client.post(
        f"/patch/rings/{ring['id']}/gate-signals",
        json={
            "signal_key": "x",
            "status": "pass",
            "source_kind": "hand-wave",
        },
    )
    assert res.status_code == 422


# Slice 4-a regression: the public manual signal endpoint
# must reject future-writer source kinds. Promotion readiness ignores
# source_kind for verdict purposes, so allowing an operator to send
# source_kind=execution would silently misrepresent provenance. The
# DB CHECK admits all five values for PRA-171/172 internal writers,
# but the public POST endpoint is constrained to "manual".


@pytest.mark.parametrize(
    "future_writer_kind", ["execution", "reboot", "probe", "external"]
)
def test_post_signal_rejects_future_writer_source_kinds_p1(
    authed_client, future_writer_kind
):
    ring = _create_ring(authed_client, f"sr-fw-{future_writer_kind}", sort_order=1)
    res = authed_client.post(
        f"/patch/rings/{ring['id']}/gate-signals",
        json={
            "signal_key": "x",
            "status": "pass",
            "source_kind": future_writer_kind,
        },
    )
    assert res.status_code == 422
    body = res.json()
    # FastAPI validation errors land in detail as a list of dicts.
    detail = body["detail"]
    if isinstance(detail, list):
        msg = " ".join(d.get("msg", "") for d in detail)
    else:
        msg = str(detail)
    assert 'must be "manual"' in msg


def test_post_signal_manual_source_kind_explicit_201(authed_client):
    """Confirm the constraint isn't over-restrictive: explicit
    source_kind="manual" is the same as omitting it."""
    ring = _create_ring(authed_client, "sr-explicit-manual", sort_order=1)
    res = authed_client.post(
        f"/patch/rings/{ring['id']}/gate-signals",
        json={
            "signal_key": "x",
            "status": "pass",
            "source_kind": "manual",
        },
    )
    assert res.status_code == 201
    assert res.json()["source_kind"] == "manual"


def test_post_signal_requires_admin_or_maintainer(client, auditor_user, authed_client):
    ring = _create_ring(authed_client, "sr-auth", sort_order=1)
    res = client.post(
        "/auth/login",
        data={"username": auditor_user.username, "password": "testpass123"},
    )
    token = res.json()["access_token"]
    res = client.post(
        f"/patch/rings/{ring['id']}/gate-signals",
        headers={"Authorization": f"Bearer {token}"},
        json={"signal_key": "x", "status": "pass"},
    )
    assert res.status_code in (401, 403)


def test_get_signals_orders_latest_first(authed_client):
    ring = _create_ring(authed_client, "sr-list", sort_order=1)
    older_ts = (datetime.utcnow() - timedelta(hours=2)).isoformat()
    newer_ts = datetime.utcnow().isoformat()
    _record_signal(
        authed_client,
        ring["id"],
        signal_key="x",
        status="pass",
        observed_at=older_ts,
    )
    _record_signal(
        authed_client,
        ring["id"],
        signal_key="x",
        status="fail",
        observed_at=newer_ts,
    )
    res = authed_client.get(f"/patch/rings/{ring['id']}/gate-signals")
    assert res.status_code == 200
    rows = res.json()
    assert rows[0]["status"] == "fail"  # latest first


def test_get_signals_filters_by_signal_key(authed_client):
    ring = _create_ring(authed_client, "sr-filter", sort_order=1)
    _record_signal(authed_client, ring["id"], signal_key="a", status="pass")
    _record_signal(authed_client, ring["id"], signal_key="b", status="pass")
    res = authed_client.get(f"/patch/rings/{ring['id']}/gate-signals?signal_key=a")
    assert res.status_code == 200
    rows = res.json()
    assert all(r["signal_key"] == "a" for r in rows)


def test_delete_signal_204(authed_client):
    ring = _create_ring(authed_client, "sr-del", sort_order=1)
    signal = _record_signal(authed_client, ring["id"], signal_key="x", status="pass")
    res = authed_client.delete(f"/patch/rings/{ring['id']}/gate-signals/{signal['id']}")
    assert res.status_code == 204


def test_delete_signal_unknown_id_404(authed_client):
    ring = _create_ring(authed_client, "sr-d404", sort_order=1)
    res = authed_client.delete(f"/patch/rings/{ring['id']}/gate-signals/999999")
    assert res.status_code == 404


# -- Promotion readiness route --------------------------------------------


def test_promotion_readiness_no_gates(authed_client):
    ring = _create_ring(authed_client, "pr-empty", sort_order=1)
    res = authed_client.get(f"/patch/rings/{ring['id']}/promotion-readiness")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "no_gates"
    assert body["enabled_gate_count"] == 0


def test_promotion_readiness_ready(authed_client):
    ring = _create_ring(authed_client, "pr-go", sort_order=1)
    _create_bool_gate(authed_client, ring["id"], signal_key="ok")
    _record_signal(authed_client, ring["id"], signal_key="ok", status="pass")
    res = authed_client.get(f"/patch/rings/{ring['id']}/promotion-readiness")
    assert res.status_code == 200
    assert res.json()["status"] == "ready"


def test_promotion_readiness_blocked(authed_client):
    ring = _create_ring(authed_client, "pr-blk", sort_order=1)
    _create_bool_gate(authed_client, ring["id"], signal_key="x")
    _record_signal(authed_client, ring["id"], signal_key="x", status="fail")
    res = authed_client.get(f"/patch/rings/{ring['id']}/promotion-readiness")
    body = res.json()
    assert body["status"] == "blocked"
    assert body["gates"][0]["gate_status"] == "failing"


def test_promotion_readiness_missing(authed_client):
    ring = _create_ring(authed_client, "pr-miss", sort_order=1)
    _create_bool_gate(authed_client, ring["id"], signal_key="needed")
    res = authed_client.get(f"/patch/rings/{ring['id']}/promotion-readiness")
    body = res.json()
    assert body["status"] == "missing_signal"
    assert body["gates"][0]["gate_status"] == "missing"


def test_promotion_readiness_disabled_ring(authed_client):
    ring = _create_ring(authed_client, "pr-off", sort_order=1, enabled=False)
    res = authed_client.get(f"/patch/rings/{ring['id']}/promotion-readiness")
    body = res.json()
    assert body["status"] == "ring_disabled"
    assert body["gates"] == []


def test_promotion_readiness_unknown_ring_404(authed_client):
    res = authed_client.get("/patch/rings/999999/promotion-readiness")
    assert res.status_code == 404


def test_promotion_readiness_inline_signal_metadata(authed_client):
    """Verdict response inlines the satisfying signal so an operator
    UI can render gate detail without a follow-up call."""
    ring = _create_ring(authed_client, "pr-inline", sort_order=1)
    _create_bool_gate(authed_client, ring["id"], signal_key="inl")
    _record_signal(
        authed_client,
        ring["id"],
        signal_key="inl",
        status="pass",
        details={"by": "ops-oncall"},
    )
    res = authed_client.get(f"/patch/rings/{ring['id']}/promotion-readiness")
    body = res.json()
    assert body["gates"][0]["signal"]["details"] == {"by": "ops-oncall"}
    assert body["gates"][0]["signal"]["status"] == "pass"


def test_promotion_readiness_visible_to_auditor(client, auditor_user, authed_client):
    ring = _create_ring(authed_client, "pr-aud", sort_order=1)
    res = client.post(
        "/auth/login",
        data={"username": auditor_user.username, "password": "testpass123"},
    )
    token = res.json()["access_token"]
    res = client.get(
        f"/patch/rings/{ring['id']}/promotion-readiness",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
