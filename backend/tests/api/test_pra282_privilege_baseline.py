"""PRA-282: the Praxis 1.0 privilege baseline (fleet-role API).

Proves the fleet-role API no longer exposes raw sudoers authoring or privileged
OS groups, and that built-in roles report no standing sudo.
"""

from __future__ import annotations

from app.db.access_models import FleetRole


def _login(client, user):
    res = client.post(
        "/auth/login", data={"username": user.username, "password": "testpass123"}
    )
    assert res.status_code == 200, res.text
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})


def test_create_role_rejects_raw_sudoers(client, db, admin_user):
    _login(client, admin_user)
    res = client.post(
        "/fleet/roles",
        json={
            "name": "pra282-raw",
            "login_mode": "per_user",
            "sudoers_snippet": "ALL=(ALL) NOPASSWD:ALL",
        },
    )
    assert res.status_code == 422
    assert "sudoers" in res.text.lower()
    # Nothing persisted.
    assert db.query(FleetRole).filter_by(name="pra282-raw").first() is None


def test_create_role_rejects_privileged_os_group(client, db, admin_user):
    _login(client, admin_user)
    for grp in ("wheel", "sudo", "root", "admin"):
        res = client.post(
            "/fleet/roles",
            json={
                "name": f"pra282-grp-{grp}",
                "login_mode": "per_user",
                "os_groups": ["docker", grp],
            },
        )
        assert res.status_code == 422, f"{grp} should be rejected"


def test_create_role_valid_is_no_sudo(client, db, admin_user):
    _login(client, admin_user)
    res = client.post(
        "/fleet/roles",
        json={
            "name": "pra282-ok",
            "login_mode": "per_user",
            "os_groups": ["docker"],
            "allowed_actions": ["session_open"],
        },
    )
    assert res.status_code == 200, res.text
    role = res.json()["role"]
    assert role["sudoers_snippet"] is None
    assert role["os_groups"] == ["docker"]
    db_role = db.query(FleetRole).filter_by(name="pra282-ok").first()
    assert db_role.sudoers_snippet is None


def test_create_role_null_sudoers_still_allowed(client, db, admin_user):
    """A backward-compatible client sending an explicit null/empty snippet is
    accepted (only a non-empty value is rejected)."""
    _login(client, admin_user)
    res = client.post(
        "/fleet/roles",
        json={"name": "pra282-null", "login_mode": "per_user", "sudoers_snippet": ""},
    )
    assert res.status_code == 200, res.text
    assert res.json()["role"]["sudoers_snippet"] is None


def test_update_role_rejects_raw_sudoers(client, db, admin_user):
    _login(client, admin_user)
    created = client.post(
        "/fleet/roles", json={"name": "pra282-upd", "login_mode": "per_user"}
    )
    assert created.status_code == 200, created.text
    rid = created.json()["role"]["id"]
    res = client.patch(
        f"/fleet/roles/{rid}", json={"sudoers_snippet": "ALL=(ALL) NOPASSWD:ALL"}
    )
    assert res.status_code == 422
    # Snippet was not applied.
    assert db.query(FleetRole).get(rid).sudoers_snippet is None


def test_update_role_rejects_privileged_group(client, db, admin_user):
    _login(client, admin_user)
    created = client.post(
        "/fleet/roles", json={"name": "pra282-updg", "login_mode": "per_user"}
    )
    rid = created.json()["role"]["id"]
    res = client.patch(f"/fleet/roles/{rid}", json={"os_groups": ["wheel"]})
    assert res.status_code == 422


def test_builtin_roles_report_no_standing_sudo(client, db, admin_user):
    _login(client, admin_user)
    res = client.get("/fleet/roles")
    assert res.status_code == 200, res.text
    by_name = {r["name"]: r for r in res.json()["roles"]}
    for name in ("admin", "maintainer", "auditor"):
        assert by_name[name]["sudoers_snippet"] is None
        assert not (
            set(by_name[name]["os_groups"]) & {"wheel", "sudo", "root", "admin"}
        )
