"""Integration tests for the systems CRUD routes and group assignment."""

from datetime import date

import pytest

from app.db.models import Distro, System


@pytest.fixture
def distro(db):
    """Local Distro fixture — conftest.distro is broken (uses non-existent columns)."""
    d = db.query(Distro).filter_by(name="Ubuntu", version="22.04").first()
    if not d:
        d = Distro(
            name="Ubuntu",
            version="22.04",
            release_date=date(2022, 4, 21),
            end_of_life_date=date(2027, 4, 1),
        )
        db.add(d)
        db.flush()
    return d


def _make_group(authed_client, name="prod-group"):
    res = authed_client.post("/groups", json={"name": name, "description": "grp"})
    assert res.status_code == 201, res.text
    return res.json()


def _make_credential(authed_client, name="sys-cred"):
    res = authed_client.post(
        "/credentials",
        json={
            "name": name,
            "auth_method": "password",
            "username": "root",
            "password": "s3cret",
            "sudo_method": "none",
        },
    )
    assert res.status_code == 201, res.text
    return res.json()


def _system_body(distro_id, group_id, cred_id, **overrides):
    body = {
        "hostname": "web-01",
        "ip_address": "10.0.0.10",
        "distro_id": distro_id,
        "status": "Active",
        "group_id": group_id,
        "credentials_id": cred_id,
        "environment": "Production",
    }
    body.update(overrides)
    return body


def test_add_system_creates_row(authed_client, mock_vault, distro, db):
    group = _make_group(authed_client)
    cred = _make_credential(authed_client)

    res = authed_client.post(
        "/systems/add-system",
        json=_system_body(distro.id, group["id"], cred["id"]),
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["hostname"] == "web-01"
    assert body["status"] == "Active"

    row = db.query(System).filter_by(hostname="web-01").one()
    assert str(row.ip_address) == "10.0.0.10"


def test_get_all_systems_returns_list(authed_client, mock_vault, distro):
    group = _make_group(authed_client, name="list-grp")
    cred = _make_credential(authed_client, name="list-cred")
    authed_client.post(
        "/systems/add-system",
        json=_system_body(
            distro.id,
            group["id"],
            cred["id"],
            hostname="lister",
            ip_address="10.0.0.11",
        ),
    )

    res = authed_client.get("/systems/all")
    assert res.status_code == 200
    hostnames = [s["hostname"] for s in res.json()]
    assert "lister" in hostnames


def test_get_system_detail(authed_client, mock_vault, distro):
    group = _make_group(authed_client, name="det-grp")
    cred = _make_credential(authed_client, name="det-cred")
    created = authed_client.post(
        "/systems/add-system",
        json=_system_body(
            distro.id,
            group["id"],
            cred["id"],
            hostname="detail-host",
            ip_address="10.0.0.12",
        ),
    ).json()

    res = authed_client.get(f"/systems/{created['id']}")
    assert res.status_code == 200
    body = res.json()
    assert body["hostname"] == "detail-host"
    assert body["group"]["id"] == group["id"]
    assert body["distribution"]["id"] == distro.id


def test_get_system_detail_404(authed_client):
    res = authed_client.get("/systems/999999")
    assert res.status_code == 404


def test_update_system(authed_client, mock_vault, distro):
    group = _make_group(authed_client, name="upd-grp")
    cred = _make_credential(authed_client, name="upd-cred")
    created = authed_client.post(
        "/systems/add-system",
        json=_system_body(
            distro.id,
            group["id"],
            cred["id"],
            hostname="upd-host",
            ip_address="10.0.0.13",
        ),
    ).json()

    res = authed_client.put(
        f"/systems/{created['id']}",
        json=_system_body(
            distro.id,
            group["id"],
            cred["id"],
            hostname="upd-host",
            ip_address="10.0.0.13",
            status="Maintenance",
        ),
    )
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "Maintenance"


def test_delete_system(authed_client, mock_vault, distro, db):
    group = _make_group(authed_client, name="del-grp")
    cred = _make_credential(authed_client, name="del-cred")
    created = authed_client.post(
        "/systems/add-system",
        json=_system_body(
            distro.id,
            group["id"],
            cred["id"],
            hostname="del-host",
            ip_address="10.0.0.14",
        ),
    ).json()

    res = authed_client.delete(f"/systems/{created['id']}")
    assert res.status_code in (200, 204)
    assert db.query(System).filter_by(id=created["id"]).first() is None


def test_auditor_cannot_create_system(client, auditor_user, mock_vault, distro):
    # Auditor logs in
    res = client.post(
        "/auth/login",
        data={"username": auditor_user.username, "password": "testpass123"},
    )
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post(
        "/systems/add-system",
        json={
            "hostname": "forbidden-host",
            "ip_address": "10.0.0.99",
            "distro_id": distro.id,
            "status": "Active",
            "group_id": 1,
            "credentials_id": 1,
        },
        headers=headers,
    )
    assert res.status_code == 403


def test_auditor_cannot_delete_system(
    authed_client, client, auditor_user, mock_vault, distro
):
    group = _make_group(authed_client, name="auditdel-grp")
    cred = _make_credential(authed_client, name="auditdel-cred")
    created = authed_client.post(
        "/systems/add-system",
        json=_system_body(
            distro.id,
            group["id"],
            cred["id"],
            hostname="auditdel-host",
            ip_address="10.0.0.15",
        ),
    ).json()

    res = client.post(
        "/auth/login",
        data={"username": auditor_user.username, "password": "testpass123"},
    )
    token = res.json()["access_token"]
    res = client.delete(
        f"/systems/{created['id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403


def test_assign_systems_to_group(authed_client, mock_vault, distro):
    group_a = _make_group(authed_client, name="assign-a")
    group_b = _make_group(authed_client, name="assign-b")
    cred = _make_credential(authed_client, name="assign-cred")
    created = authed_client.post(
        "/systems/add-system",
        json=_system_body(
            distro.id,
            group_a["id"],
            cred["id"],
            hostname="move-host",
            ip_address="10.0.0.16",
        ),
    ).json()

    res = authed_client.post(
        f"/groups/{group_b['id']}/systems",
        json={"system_ids": [created["id"]]},
    )
    assert res.status_code == 200, res.text
    assert "Successfully assigned" in res.json()["message"]

    # Verify system now in group_b
    detail = authed_client.get(f"/systems/{created['id']}").json()
    assert detail["group"]["id"] == group_b["id"]
