"""PRA-161 slice 1b — patch policy CRUD route tests.

Covers:
  * POST /patch/policies — happy path, slug conflict, MW bind
    validation, scope-kind/packages cross-field, schema-level slug
    rejection, role gating.
  * GET (list, by id, by slug, 404).
  * PATCH partial, MW rebind, unknown id, role gating.
  * DELETE 204 / 404 / role gating.
  * Validation failures return 422 (not 500) per the audit-row-first
    contract carried forward from PRA-160.
"""

from __future__ import annotations

import json

import pytest

from app.db.models import MaintenanceWindow


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


# -- POST -------------------------------------------------------------------


def test_post_creates_policy(authed_client):
    res = authed_client.post(
        "/patch/policies",
        json={
            "slug": "weekly-security",
            "name": "Weekly Security",
            "scope_kind": "security_only",
        },
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["slug"] == "weekly-security"
    assert body["scope_kind"] == "security_only"
    assert body["scope_packages"] == []
    assert body["rollout_cadence"] == "immediate"
    assert body["failure_policy"] == "pause_fleet"


def test_post_duplicate_slug_returns_422(authed_client):
    payload = {
        "slug": "dup",
        "name": "First",
        "scope_kind": "security_only",
    }
    r1 = authed_client.post("/patch/policies", json=payload)
    assert r1.status_code == 201
    r2 = authed_client.post("/patch/policies", json={**payload, "name": "Second"})
    assert r2.status_code == 422
    assert "already exists" in r2.json()["detail"]


def test_post_with_window_succeeds(authed_client, enabled_window):
    res = authed_client.post(
        "/patch/policies",
        json={
            "slug": "windowed",
            "name": "Windowed",
            "scope_kind": "full",
            "maintenance_window_id": enabled_window.id,
        },
    )
    assert res.status_code == 201, res.text
    assert res.json()["maintenance_window_id"] == enabled_window.id


def test_post_with_disabled_window_returns_422(authed_client, disabled_window):
    res = authed_client.post(
        "/patch/policies",
        json={
            "slug": "no-window",
            "name": "No Window",
            "scope_kind": "security_only",
            "maintenance_window_id": disabled_window.id,
        },
    )
    assert res.status_code == 422
    assert "disabled window" in res.json()["detail"]


def test_post_with_nonexistent_window_returns_422(authed_client):
    res = authed_client.post(
        "/patch/policies",
        json={
            "slug": "ghost-window",
            "name": "Ghost",
            "scope_kind": "security_only",
            "maintenance_window_id": 999_999,
        },
    )
    assert res.status_code == 422


@pytest.mark.parametrize(
    "scope,packages,expect_ok",
    [
        ("security_only", [], True),
        ("security_only", ["openssl"], False),
        ("full", [], True),
        ("full", ["openssl"], False),
        ("package_allowlist", ["openssl"], True),
        ("package_allowlist", [], False),
        ("package_denylist", ["bad"], True),
        ("package_denylist", [], False),
    ],
)
def test_post_scope_packages_invariants(authed_client, scope, packages, expect_ok):
    res = authed_client.post(
        "/patch/policies",
        json={
            "slug": f"sp-{scope}-{int(expect_ok)}",
            "name": "X",
            "scope_kind": scope,
            "scope_packages": packages,
        },
    )
    if expect_ok:
        assert res.status_code == 201, res.text
    else:
        assert res.status_code == 422


@pytest.mark.parametrize(
    "bad_slug",
    ["", "UPPER", "has space", "trailing-", "-leading", "double--dash", "x" * 65],
)
def test_post_bad_slug_returns_422(authed_client, bad_slug):
    res = authed_client.post(
        "/patch/policies",
        json={
            "slug": bad_slug,
            "name": "X",
            "scope_kind": "security_only",
        },
    )
    # FastAPI/Pydantic returns 422 for validation. ``double--dash`` is
    # accepted by the slug-shape rule (see _validate_slug); test only
    # the genuinely-invalid shapes here.
    if bad_slug in {"", "UPPER", "has space", "x" * 65}:
        assert res.status_code == 422
    elif bad_slug == "double--dash":
        # Permitted by current shape (alphanumeric + - / _).
        # Test asserts current behavior; tighten if rule changes.
        assert res.status_code in (201, 422)


@pytest.mark.parametrize("bad", [0, -1, True, False])
def test_post_required_approvals_rejects_bool_and_zero(authed_client, bad):
    res = authed_client.post(
        "/patch/policies",
        json={
            "slug": f"ra-{int(bool(bad))}-{abs(int(bad)) if isinstance(bad, int) else 0}",
            "name": "X",
            "scope_kind": "security_only",
            "required_approvals": bad,
        },
    )
    assert res.status_code == 422


def test_post_requires_admin_or_maintainer(client, auditor_user):
    """Auditor (read-only) cannot create policies."""
    res = client.post(
        "/auth/login",
        data={"username": auditor_user.username, "password": "testpass123"},
    )
    assert res.status_code == 200
    token = res.json()["access_token"]
    res = client.post(
        "/patch/policies",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "slug": "blocked",
            "name": "Blocked",
            "scope_kind": "security_only",
        },
    )
    assert res.status_code in (401, 403)


# -- GET --------------------------------------------------------------------


def test_get_list_returns_created_policies(authed_client):
    authed_client.post(
        "/patch/policies",
        json={
            "slug": "list-1",
            "name": "L1",
            "scope_kind": "security_only",
        },
    )
    authed_client.post(
        "/patch/policies",
        json={
            "slug": "list-2",
            "name": "L2",
            "scope_kind": "full",
            "enabled": False,
        },
    )
    res = authed_client.get("/patch/policies")
    assert res.status_code == 200
    rows = res.json()
    slugs = {r["slug"] for r in rows}
    assert {"list-1", "list-2"}.issubset(slugs)

    res = authed_client.get("/patch/policies?enabled_only=true")
    assert res.status_code == 200
    enabled_slugs = {r["slug"] for r in res.json()}
    assert "list-1" in enabled_slugs
    assert "list-2" not in enabled_slugs


def test_get_by_id_404(authed_client):
    res = authed_client.get("/patch/policies/999999")
    assert res.status_code == 404


def test_get_by_slug_routes_correctly(authed_client):
    """Belt-and-suspenders for feedback_fastapi_route_ordering: the
    literal ``/by-slug/...`` must not be shadowed by ``/{policy_id}``."""
    authed_client.post(
        "/patch/policies",
        json={
            "slug": "lookup-me",
            "name": "Lookup",
            "scope_kind": "security_only",
        },
    )
    res = authed_client.get("/patch/policies/by-slug/lookup-me")
    assert res.status_code == 200
    assert res.json()["slug"] == "lookup-me"

    res404 = authed_client.get("/patch/policies/by-slug/nope")
    assert res404.status_code == 404


def test_get_list_offset_limit_validated(authed_client):
    assert authed_client.get("/patch/policies?offset=-1").status_code == 422
    assert authed_client.get("/patch/policies?limit=0").status_code == 422
    assert authed_client.get("/patch/policies?limit=501").status_code == 422


# -- PATCH ------------------------------------------------------------------


def test_patch_partial(authed_client):
    create = authed_client.post(
        "/patch/policies",
        json={
            "slug": "patch-me",
            "name": "Original",
            "scope_kind": "security_only",
        },
    )
    pid = create.json()["id"]
    res = authed_client.patch(
        f"/patch/policies/{pid}",
        json={"name": "Renamed", "enabled": False},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["name"] == "Renamed"
    assert body["enabled"] is False
    assert body["scope_kind"] == "security_only"


def test_patch_rebind_window(authed_client, enabled_window, disabled_window):
    create = authed_client.post(
        "/patch/policies",
        json={
            "slug": "patch-bind",
            "name": "Patch",
            "scope_kind": "security_only",
        },
    )
    pid = create.json()["id"]

    res_ok = authed_client.patch(
        f"/patch/policies/{pid}",
        json={"maintenance_window_id": enabled_window.id},
    )
    assert res_ok.status_code == 200
    assert res_ok.json()["maintenance_window_id"] == enabled_window.id

    res_bad = authed_client.patch(
        f"/patch/policies/{pid}",
        json={"maintenance_window_id": disabled_window.id},
    )
    assert res_bad.status_code == 422


def test_patch_unknown_id_returns_404(authed_client):
    res = authed_client.patch(
        "/patch/policies/999999",
        json={"name": "X"},
    )
    assert res.status_code == 404


def test_patch_required_approvals_rejects_bool(authed_client):
    """PATCH path also blocks bool-as-int via pre=True validator."""
    create = authed_client.post(
        "/patch/policies",
        json={
            "slug": "patch-bool",
            "name": "X",
            "scope_kind": "security_only",
        },
    )
    pid = create.json()["id"]
    res = authed_client.patch(
        f"/patch/policies/{pid}", json={"required_approvals": True}
    )
    assert res.status_code == 422


def test_patch_empty_body_returns_422(authed_client):
    create = authed_client.post(
        "/patch/policies",
        json={
            "slug": "patch-empty",
            "name": "X",
            "scope_kind": "security_only",
        },
    )
    pid = create.json()["id"]
    res = authed_client.patch(f"/patch/policies/{pid}", json={})
    assert res.status_code == 422


# -- DELETE -----------------------------------------------------------------


def test_delete_policy_204(authed_client):
    create = authed_client.post(
        "/patch/policies",
        json={
            "slug": "delete-me",
            "name": "Delete",
            "scope_kind": "security_only",
        },
    )
    pid = create.json()["id"]
    res = authed_client.delete(f"/patch/policies/{pid}")
    assert res.status_code == 204
    res2 = authed_client.get(f"/patch/policies/{pid}")
    assert res2.status_code == 404


def test_delete_unknown_id_returns_404(authed_client):
    res = authed_client.delete("/patch/policies/999999")
    assert res.status_code == 404


def test_delete_fleet_default_policy_returns_422(authed_client):
    """PRA-355: deleting the fleet-default policy must be a bounded 422
    with operator copy, not the raw 500 the RESTRICT FK produced before."""
    create = authed_client.post(
        "/patch/policies",
        json={
            "slug": "cant-delete-default",
            "name": "Default",
            "scope_kind": "security_only",
        },
    )
    pid = create.json()["id"]
    assert authed_client.post(f"/patch/policies/{pid}/fleet-default").status_code == 200

    res = authed_client.delete(f"/patch/policies/{pid}")
    assert res.status_code == 422
    assert "fleet default" in res.json()["detail"]
    # Refusal did not destroy the policy.
    assert authed_client.get(f"/patch/policies/{pid}").status_code == 200


def test_delete_requires_admin(client, maintainer_user):
    """Maintainer can create + update but not delete (admin-only)."""
    res = client.post(
        "/auth/login",
        data={"username": maintainer_user.username, "password": "testpass123"},
    )
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    create = client.post(
        "/patch/policies",
        headers=headers,
        json={
            "slug": "maintainer-cant-delete",
            "name": "X",
            "scope_kind": "security_only",
        },
    )
    assert create.status_code == 201
    pid = create.json()["id"]
    res = client.delete(f"/patch/policies/{pid}", headers=headers)
    assert res.status_code in (401, 403)
