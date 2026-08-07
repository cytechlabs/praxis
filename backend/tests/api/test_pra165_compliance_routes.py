"""PRA-165 slice 1 — compliance CRUD route tests.

Covers:

* POST/GET/PATCH/DELETE on /compliance/policies — happy paths,
  validation errors → 422, missing → 404, RBAC enforcement.
* POST/PATCH/DELETE on /compliance/policies/{id}/checks +
  /compliance/checks/{id} — typed definition validation and RBAC.
* GET /compliance/starter-pack — preview shape.
* POST /compliance/starter-pack/seed — admin-only + idempotency over HTTP.
* Read surfaces explicitly expose ``runner_status`` + ``runner_owner``.
"""

from __future__ import annotations

import pytest


def _login(client, user):
    res = client.post(
        "/auth/login",
        data={"username": user.username, "password": "testpass123"},
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Policy CRUD
# ---------------------------------------------------------------------------


def test_post_creates_policy(authed_client):
    res = authed_client.post(
        "/compliance/policies",
        json={
            "slug": "ssh-baseline",
            "name": "SSH Baseline",
            "severity": "high",
            "category": "access-control",
        },
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["slug"] == "ssh-baseline"
    assert body["severity"] == "high"
    assert body["category"] == "access-control"
    assert body["enabled"] is True
    assert body["version"] == 1
    assert body["built_in"] is False
    # Read surface MUST serialize timestamps as absolute UTC ending in 'Z'
    # (Slice 1 read-wire lock; no local-time strings on persisted rows).
    assert isinstance(body["created_at"], str) and body["created_at"].endswith("Z")
    assert isinstance(body["updated_at"], str) and body["updated_at"].endswith("Z")


def test_post_duplicate_slug_returns_422(authed_client):
    payload = {"slug": "dup", "name": "First"}
    r1 = authed_client.post("/compliance/policies", json=payload)
    assert r1.status_code == 201
    r2 = authed_client.post("/compliance/policies", json={**payload, "name": "Second"})
    assert r2.status_code == 422
    assert "already exists" in r2.json()["detail"]


def test_post_invalid_slug_returns_422(authed_client):
    res = authed_client.post(
        "/compliance/policies",
        json={"slug": "UPPER", "name": "Bad"},
    )
    assert res.status_code == 422


def test_post_invalid_severity_returns_422(authed_client):
    res = authed_client.post(
        "/compliance/policies",
        json={"slug": "ok", "name": "Ok", "severity": "catastrophic"},
    )
    assert res.status_code == 422


def test_post_requires_write_role(client, auditor_user):
    token = _login(client, auditor_user)
    res = client.post(
        "/compliance/policies",
        headers=_bearer(token),
        json={"slug": "blocked", "name": "Blocked"},
    )
    assert res.status_code in (401, 403)


def test_maintainer_can_create_policy(client, maintainer_user):
    token = _login(client, maintainer_user)
    res = client.post(
        "/compliance/policies",
        headers=_bearer(token),
        json={"slug": "by-maint", "name": "By Maint"},
    )
    assert res.status_code == 201, res.text


def test_get_list_returns_created_policies(authed_client):
    authed_client.post("/compliance/policies", json={"slug": "l1", "name": "L1"})
    authed_client.post(
        "/compliance/policies",
        json={"slug": "l2", "name": "L2", "enabled": False},
    )
    res = authed_client.get("/compliance/policies")
    assert res.status_code == 200
    slugs = {r["slug"] for r in res.json()}
    assert {"l1", "l2"}.issubset(slugs)


def test_get_list_filters_enabled_only(authed_client):
    authed_client.post("/compliance/policies", json={"slug": "on", "name": "On"})
    authed_client.post(
        "/compliance/policies",
        json={"slug": "off", "name": "Off", "enabled": False},
    )
    res = authed_client.get("/compliance/policies?enabled_only=true")
    slugs = {r["slug"] for r in res.json()}
    assert "on" in slugs and "off" not in slugs


def test_auditor_can_read_list(client, auditor_user, authed_client):
    """Auditor (read-only) MUST be able to read policies, even
    though they cannot create them.
    """
    authed_client.post("/compliance/policies", json={"slug": "vis", "name": "Vis"})
    token = _login(client, auditor_user)
    res = client.get("/compliance/policies", headers=_bearer(token))
    assert res.status_code == 200
    slugs = {r["slug"] for r in res.json()}
    assert "vis" in slugs


def test_get_by_slug_returns_detail_with_checks(authed_client):
    authed_client.post(
        "/compliance/policies", json={"slug": "with-checks", "name": "WC"}
    )
    pid = authed_client.get("/compliance/policies/by-slug/with-checks").json()["id"]
    authed_client.post(
        f"/compliance/policies/{pid}/checks",
        json={
            "slug": "ssh-pkg",
            "title": "openssh-server installed",
            "kind": "package_installed",
            "definition": {"package": "openssh-server"},
        },
    )
    res = authed_client.get("/compliance/policies/by-slug/with-checks")
    assert res.status_code == 200
    body = res.json()
    assert body["slug"] == "with-checks"
    assert len(body["checks"]) == 1
    assert body["checks"][0]["kind"] == "package_installed"
    # Read surface MUST surface runner_status + runner_owner explicitly.
    assert body["checks"][0]["runner_status"] == "runner_not_implemented_in_slice_1"
    assert body["checks"][0]["runner_owner"] == "deferred_to_pra165_slice_2"
    # Embedded-check timestamps must be absolute UTC ending in 'Z'.
    assert body["checks"][0]["created_at"].endswith("Z")
    assert body["checks"][0]["updated_at"].endswith("Z")
    # Detail-envelope policy timestamps likewise end in 'Z'.
    assert body["created_at"].endswith("Z")
    assert body["updated_at"].endswith("Z")


def test_get_by_slug_404(authed_client):
    res = authed_client.get("/compliance/policies/by-slug/nope")
    assert res.status_code == 404


def test_get_by_id_404(authed_client):
    res = authed_client.get("/compliance/policies/999999")
    assert res.status_code == 404


def test_patch_policy_partial(authed_client):
    pid = authed_client.post(
        "/compliance/policies", json={"slug": "edit", "name": "Edit"}
    ).json()["id"]
    res = authed_client.patch(
        f"/compliance/policies/{pid}",
        json={"name": "Edited", "severity": "high"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["name"] == "Edited"
    assert body["severity"] == "high"
    assert body["version"] == 2


def test_patch_policy_unknown_id_returns_404(authed_client):
    res = authed_client.patch(
        "/compliance/policies/999999",
        json={"name": "Edited"},
    )
    assert res.status_code == 404


def test_patch_policy_empty_body_422(authed_client):
    pid = authed_client.post(
        "/compliance/policies", json={"slug": "empty", "name": "Empty"}
    ).json()["id"]
    res = authed_client.patch(f"/compliance/policies/{pid}", json={})
    assert res.status_code == 422


def test_patch_policy_requires_write_role(client, auditor_user, authed_client):
    pid = authed_client.post(
        "/compliance/policies", json={"slug": "rbac", "name": "RBAC"}
    ).json()["id"]
    token = _login(client, auditor_user)
    res = client.patch(
        f"/compliance/policies/{pid}",
        headers=_bearer(token),
        json={"name": "Auditor Hijack"},
    )
    assert res.status_code in (401, 403)


def test_post_enabled_toggle(authed_client):
    pid = authed_client.post(
        "/compliance/policies", json={"slug": "tog", "name": "Tog"}
    ).json()["id"]
    res = authed_client.post(
        f"/compliance/policies/{pid}/enabled", json={"enabled": False}
    )
    assert res.status_code == 200
    assert res.json()["enabled"] is False


def test_delete_policy_204(authed_client):
    pid = authed_client.post(
        "/compliance/policies", json={"slug": "byebye", "name": "Bye"}
    ).json()["id"]
    res = authed_client.delete(f"/compliance/policies/{pid}")
    assert res.status_code == 204
    assert authed_client.get(f"/compliance/policies/{pid}").status_code == 404


def test_delete_requires_admin(client, maintainer_user, authed_client):
    pid = authed_client.post(
        "/compliance/policies", json={"slug": "maint-del", "name": "MD"}
    ).json()["id"]
    token = _login(client, maintainer_user)
    res = client.delete(f"/compliance/policies/{pid}", headers=_bearer(token))
    assert res.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Check sub-resource
# ---------------------------------------------------------------------------


@pytest.fixture
def policy_id(authed_client) -> int:
    return authed_client.post(
        "/compliance/policies", json={"slug": "cf", "name": "Checks Fixture"}
    ).json()["id"]


def test_add_check_happy_path(authed_client, policy_id):
    res = authed_client.post(
        f"/compliance/policies/{policy_id}/checks",
        json={
            "slug": "openssh",
            "title": "openssh-server installed",
            "kind": "package_installed",
            "definition": {"package": "openssh-server"},
        },
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["kind"] == "package_installed"
    assert body["definition"] == {"package": "openssh-server"}
    assert body["runner_owner"] == "deferred_to_pra165_slice_2"
    # Check create response timestamps must be absolute UTC ending in 'Z'.
    assert body["created_at"].endswith("Z")
    assert body["updated_at"].endswith("Z")


def test_add_check_unknown_kind_422(authed_client, policy_id):
    res = authed_client.post(
        f"/compliance/policies/{policy_id}/checks",
        json={
            "slug": "bad",
            "title": "Bad",
            "kind": "openscap_xccdf",  # OpenSCAP is OUT
            "definition": {},
        },
    )
    assert res.status_code == 422
    assert "unknown check kind" in res.json()["detail"]


def test_add_check_bad_definition_422(authed_client, policy_id):
    res = authed_client.post(
        f"/compliance/policies/{policy_id}/checks",
        json={
            "slug": "badpath",
            "title": "Bad Path",
            "kind": "file_exists",
            "definition": {"path": "relative/path"},
        },
    )
    assert res.status_code == 422


def test_add_check_requires_write_role(client, auditor_user, authed_client, policy_id):
    token = _login(client, auditor_user)
    res = client.post(
        f"/compliance/policies/{policy_id}/checks",
        headers=_bearer(token),
        json={
            "slug": "denied",
            "title": "Denied",
            "kind": "package_installed",
            "definition": {"package": "openssh-server"},
        },
    )
    assert res.status_code in (401, 403)


def test_list_checks(authed_client, policy_id):
    authed_client.post(
        f"/compliance/policies/{policy_id}/checks",
        json={
            "slug": "a",
            "title": "A",
            "kind": "package_installed",
            "definition": {"package": "openssh-server"},
        },
    )
    res = authed_client.get(f"/compliance/policies/{policy_id}/checks")
    assert res.status_code == 200
    rows = res.json()
    assert len(rows) == 1
    assert rows[0]["slug"] == "a"
    assert "runner_status" in rows[0]
    # Listed-check timestamps must be absolute UTC ending in 'Z'.
    assert rows[0]["created_at"].endswith("Z")
    assert rows[0]["updated_at"].endswith("Z")


def test_patch_check(authed_client, policy_id):
    check_id = authed_client.post(
        f"/compliance/policies/{policy_id}/checks",
        json={
            "slug": "p",
            "title": "P",
            "kind": "package_installed",
            "definition": {"package": "openssh-server"},
        },
    ).json()["id"]
    res = authed_client.patch(
        f"/compliance/checks/{check_id}",
        json={
            "title": "P Renamed",
            "definition": {"package": "auditd"},
            "enabled": False,
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert body["title"] == "P Renamed"
    assert body["definition"]["package"] == "auditd"
    assert body["enabled"] is False


def test_delete_check_204(authed_client, policy_id):
    check_id = authed_client.post(
        f"/compliance/policies/{policy_id}/checks",
        json={
            "slug": "d",
            "title": "D",
            "kind": "package_installed",
            "definition": {"package": "openssh-server"},
        },
    ).json()["id"]
    res = authed_client.delete(f"/compliance/checks/{check_id}")
    assert res.status_code == 204


# ---------------------------------------------------------------------------
# Starter pack
# ---------------------------------------------------------------------------


def test_starter_pack_preview(authed_client):
    res = authed_client.get("/compliance/starter-pack")
    assert res.status_code == 200
    rows = res.json()
    assert rows, "starter pack must not be empty"
    for row in rows:
        assert row["check_count"] >= 1
        assert row["runner_owners"]


def test_starter_pack_seed_admin_only(client, maintainer_user):
    token = _login(client, maintainer_user)
    res = client.post("/compliance/starter-pack/seed", headers=_bearer(token))
    assert res.status_code in (401, 403)


def test_starter_pack_seed_is_idempotent(authed_client):
    first = authed_client.post("/compliance/starter-pack/seed")
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert first_body["seeded"], "first seed should insert rows"
    assert first_body["skipped"] == []

    second = authed_client.post("/compliance/starter-pack/seed")
    assert second.status_code == 200
    second_body = second.json()
    assert second_body["seeded"] == []
    assert sorted(second_body["skipped"]) == sorted(first_body["seeded"])

    listing = authed_client.get("/compliance/policies?built_in_only=true").json()
    assert {p["slug"] for p in listing} >= {
        "package-hygiene",
        "ssh-baseline",
    }


def test_built_in_starter_policy_cannot_be_deleted(authed_client):
    authed_client.post("/compliance/starter-pack/seed")
    pid = authed_client.get("/compliance/policies/by-slug/package-hygiene").json()["id"]
    res = authed_client.delete(f"/compliance/policies/{pid}")
    assert res.status_code == 422
    assert "built-in" in res.json()["detail"]
