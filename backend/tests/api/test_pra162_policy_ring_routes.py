"""PRA-162 slice 3 — route tests for /patch/policies/{id}/rings + readiness."""

from __future__ import annotations

# -- Helpers ---------------------------------------------------------------


def _create_policy(authed_client, slug, *, rollout_cadence="staged", enabled=False):
    """Default ``enabled=False`` so the P1 create-time guard is not
    tripped on every fixture. Tests that need an enabled staged
    policy bind a ring and then PATCH ``enabled=True``."""
    res = authed_client.post(
        "/patch/policies",
        json={
            "slug": slug,
            "name": slug,
            "scope_kind": "security_only",
            "rollout_cadence": rollout_cadence,
            "enabled": enabled,
        },
    )
    assert res.status_code == 201, res.text
    return res.json()


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


# -- POST /patch/policies/{id}/rings --------------------------------------


def test_post_ring_201_returns_inline_ring_metadata(authed_client):
    policy = _create_policy(authed_client, "rt-ok")
    ring = _create_ring(authed_client, "rt-ok-ring", sort_order=1)
    res = authed_client.post(
        f"/patch/policies/{policy['id']}/rings",
        json={"ring_id": ring["id"]},
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["policy_id"] == policy["id"]
    assert body["ring_id"] == ring["id"]
    assert body["ring_slug"] == "rt-ok-ring"
    assert body["ring_sort_order"] == 1
    assert body["ring_enabled"] is True


def test_post_immediate_policy_rejected_422(authed_client):
    policy = _create_policy(authed_client, "rt-imm", rollout_cadence="immediate")
    ring = _create_ring(authed_client, "rt-imm-ring", sort_order=1)
    res = authed_client.post(
        f"/patch/policies/{policy['id']}/rings",
        json={"ring_id": ring["id"]},
    )
    assert res.status_code == 422
    assert "not staged" in res.json()["detail"]


def test_post_disabled_ring_rejected_422(authed_client):
    policy = _create_policy(authed_client, "rt-off")
    ring = _create_ring(authed_client, "rt-off-ring", sort_order=1, enabled=False)
    res = authed_client.post(
        f"/patch/policies/{policy['id']}/rings",
        json={"ring_id": ring["id"]},
    )
    assert res.status_code == 422
    assert "disabled" in res.json()["detail"]


def test_post_unknown_policy_404(authed_client):
    ring = _create_ring(authed_client, "rt-orphan", sort_order=1)
    res = authed_client.post(
        "/patch/policies/999999/rings",
        json={"ring_id": ring["id"]},
    )
    assert res.status_code == 404


def test_post_unknown_ring_422(authed_client):
    policy = _create_policy(authed_client, "rt-no-ring")
    res = authed_client.post(
        f"/patch/policies/{policy['id']}/rings",
        json={"ring_id": 999999},
    )
    assert res.status_code == 422


def test_post_duplicate_pair_422(authed_client):
    policy = _create_policy(authed_client, "rt-dup")
    ring = _create_ring(authed_client, "rt-dup-ring", sort_order=1)
    authed_client.post(
        f"/patch/policies/{policy['id']}/rings",
        json={"ring_id": ring["id"]},
    )
    res = authed_client.post(
        f"/patch/policies/{policy['id']}/rings",
        json={"ring_id": ring["id"]},
    )
    assert res.status_code == 422
    assert "already bound" in res.json()["detail"]


def test_post_requires_admin_or_maintainer(client, auditor_user, authed_client):
    policy = _create_policy(authed_client, "rt-auth")
    ring = _create_ring(authed_client, "rt-auth-ring", sort_order=1)
    res = client.post(
        "/auth/login",
        data={"username": auditor_user.username, "password": "testpass123"},
    )
    token = res.json()["access_token"]
    res = client.post(
        f"/patch/policies/{policy['id']}/rings",
        headers={"Authorization": f"Bearer {token}"},
        json={"ring_id": ring["id"]},
    )
    assert res.status_code in (401, 403)


# -- GET /patch/policies/{id}/rings ---------------------------------------


def test_get_rings_orders_by_sort_order(authed_client):
    policy = _create_policy(authed_client, "rt-list")
    a = _create_ring(authed_client, "x-low", sort_order=1)
    b = _create_ring(authed_client, "y-mid", sort_order=2)
    c = _create_ring(authed_client, "z-high", sort_order=3)
    for r in (c, a, b):  # bind out of order
        authed_client.post(
            f"/patch/policies/{policy['id']}/rings",
            json={"ring_id": r["id"]},
        )

    res = authed_client.get(f"/patch/policies/{policy['id']}/rings")
    assert res.status_code == 200
    body = res.json()
    assert [r["ring_slug"] for r in body["rings"]] == ["x-low", "y-mid", "z-high"]


def test_get_rings_unknown_policy_404(authed_client):
    res = authed_client.get("/patch/policies/999999/rings")
    assert res.status_code == 404


def test_get_rings_visible_to_auditor(client, auditor_user, authed_client):
    policy = _create_policy(authed_client, "rt-read")
    res = client.post(
        "/auth/login",
        data={"username": auditor_user.username, "password": "testpass123"},
    )
    token = res.json()["access_token"]
    res = client.get(
        f"/patch/policies/{policy['id']}/rings",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200


# -- DELETE /patch/policies/{id}/rings/{ring_id} --------------------------


def test_delete_ring_binding_204(authed_client):
    policy = _create_policy(authed_client, "rt-del")
    a = _create_ring(authed_client, "del-a", sort_order=1)
    b = _create_ring(authed_client, "del-b", sort_order=2)
    authed_client.post(
        f"/patch/policies/{policy['id']}/rings", json={"ring_id": a["id"]}
    )
    authed_client.post(
        f"/patch/policies/{policy['id']}/rings", json={"ring_id": b["id"]}
    )
    res = authed_client.delete(f"/patch/policies/{policy['id']}/rings/{a['id']}")
    assert res.status_code == 204


def test_delete_unknown_pair_422(authed_client):
    policy = _create_policy(authed_client, "rt-uu")
    ring = _create_ring(authed_client, "rt-uu-ring", sort_order=1)
    res = authed_client.delete(f"/patch/policies/{policy['id']}/rings/{ring['id']}")
    assert res.status_code == 422


def test_delete_unknown_policy_404(authed_client):
    res = authed_client.delete("/patch/policies/999999/rings/1")
    assert res.status_code == 404


def test_delete_last_enabled_ring_from_enabled_policy_422(authed_client):
    # Create disabled, bind, then enable — that's the legal path to an
    # enabled+staged policy under draft mode.
    policy = _create_policy(authed_client, "rt-last")
    ring = _create_ring(authed_client, "last", sort_order=1)
    authed_client.post(
        f"/patch/policies/{policy['id']}/rings", json={"ring_id": ring["id"]}
    )
    enable_res = authed_client.patch(
        f"/patch/policies/{policy['id']}", json={"enabled": True}
    )
    assert enable_res.status_code == 200, enable_res.text

    res = authed_client.delete(f"/patch/policies/{policy['id']}/rings/{ring['id']}")
    assert res.status_code == 422
    assert "last enabled ring" in res.json()["detail"]


# -- GET /patch/policies/{id}/staged-readiness ----------------------------


def test_readiness_immediate_policy(authed_client):
    policy = _create_policy(authed_client, "rt-imm-ready", rollout_cadence="immediate")
    res = authed_client.get(f"/patch/policies/{policy['id']}/staged-readiness")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "not_staged"


def test_readiness_ready_after_binding_enabled_ring(authed_client):
    policy = _create_policy(authed_client, "rt-ready")
    ring = _create_ring(authed_client, "ready-ring", sort_order=1)
    authed_client.post(
        f"/patch/policies/{policy['id']}/rings", json={"ring_id": ring["id"]}
    )
    res = authed_client.get(f"/patch/policies/{policy['id']}/staged-readiness")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ready"
    assert body["enabled_ring_count"] == 1


def test_readiness_missing_ring_set(authed_client):
    policy = _create_policy(authed_client, "rt-miss", enabled=False)
    res = authed_client.get(f"/patch/policies/{policy['id']}/staged-readiness")
    assert res.status_code == 200
    assert res.json()["status"] == "missing_ring_set"


def test_readiness_no_enabled_rings(authed_client, db):
    from app.db.models import PatchRing  # local import to keep top of file lean

    policy = _create_policy(authed_client, "rt-stale")
    ring = _create_ring(authed_client, "stale", sort_order=1)
    authed_client.post(
        f"/patch/policies/{policy['id']}/rings", json={"ring_id": ring["id"]}
    )
    # Disable the ring at the DB layer (avoids the slug-immutable surface
    # of any future PATCH route).
    row = db.query(PatchRing).filter(PatchRing.id == ring["id"]).first()
    row.enabled = False
    db.commit()

    res = authed_client.get(f"/patch/policies/{policy['id']}/staged-readiness")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "no_enabled_rings"
    assert body["ring_count"] == 1
    assert body["enabled_ring_count"] == 0


def test_readiness_unknown_policy_404(authed_client):
    res = authed_client.get("/patch/policies/999999/staged-readiness")
    assert res.status_code == 404


# -- update_policy guard via route ----------------------------------------


def test_patch_policy_enable_without_rings_returns_422(authed_client):
    policy = _create_policy(authed_client, "rt-enable", enabled=False)
    res = authed_client.patch(
        f"/patch/policies/{policy['id']}",
        json={"enabled": True},
    )
    assert res.status_code == 422
    assert "no enabled bound rings" in res.json()["detail"]


def test_patch_policy_enable_with_rings_succeeds(authed_client):
    policy = _create_policy(authed_client, "rt-enable-ok", enabled=False)
    ring = _create_ring(authed_client, "enable-ok", sort_order=1)
    authed_client.post(
        f"/patch/policies/{policy['id']}/rings", json={"ring_id": ring["id"]}
    )
    res = authed_client.patch(
        f"/patch/policies/{policy['id']}",
        json={"enabled": True},
    )
    assert res.status_code == 200
    assert res.json()["enabled"] is True


# -- Slice 3-a regression: P1 create-time guard, P2 staged→immediate guard


def test_post_enabled_staged_policy_rejected_422_p1(authed_client):
    """A fresh staged policy has no rings yet by
    definition, so POST /patch/policies with rollout_cadence='staged'
    + enabled=true must be rejected."""
    res = authed_client.post(
        "/patch/policies",
        json={
            "slug": "p1-rt-enabled-staged",
            "name": "p1",
            "scope_kind": "security_only",
            "rollout_cadence": "staged",
            "enabled": True,
        },
    )
    assert res.status_code == 422
    detail = res.json()["detail"]
    assert "enabled staged policy" in detail
    assert "without ring bindings" in detail


def test_post_disabled_staged_policy_allowed_p1(authed_client):
    res = authed_client.post(
        "/patch/policies",
        json={
            "slug": "p1-rt-draft",
            "name": "draft",
            "scope_kind": "security_only",
            "rollout_cadence": "staged",
            "enabled": False,
        },
    )
    assert res.status_code == 201
    body = res.json()
    assert body["enabled"] is False
    assert body["rollout_cadence"] == "staged"


def test_patch_staged_to_immediate_with_bindings_returns_422_p2(authed_client):
    """Rolling staged → immediate while ring bindings
    still exist must be rejected via the route."""
    policy = _create_policy(authed_client, "p2-rt-staged")
    ring = _create_ring(authed_client, "p2-rt-ring", sort_order=1)
    authed_client.post(
        f"/patch/policies/{policy['id']}/rings", json={"ring_id": ring["id"]}
    )
    res = authed_client.patch(
        f"/patch/policies/{policy['id']}",
        json={"rollout_cadence": "immediate"},
    )
    assert res.status_code == 422
    detail = res.json()["detail"]
    assert "to immediate" in detail
    assert "ring bindings" in detail


def test_patch_staged_to_immediate_after_unbind_succeeds_p2(authed_client):
    policy = _create_policy(authed_client, "p2-rt-clean")
    ring = _create_ring(authed_client, "p2-rt-clean-ring", sort_order=1)
    authed_client.post(
        f"/patch/policies/{policy['id']}/rings", json={"ring_id": ring["id"]}
    )
    # Disabled draft, so unbinding the only ring is allowed.
    authed_client.delete(f"/patch/policies/{policy['id']}/rings/{ring['id']}")
    res = authed_client.patch(
        f"/patch/policies/{policy['id']}",
        json={"rollout_cadence": "immediate"},
    )
    assert res.status_code == 200
    assert res.json()["rollout_cadence"] == "immediate"
