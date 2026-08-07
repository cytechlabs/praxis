"""PRA-348: `/systems/all` exposes `last_audited` so the Available Updates page's
`Last checked` value rehydrates from the backend across navigation/reload.
"""

from datetime import date, datetime

import pytest

from app.db.models import Distro, System


@pytest.fixture
def distro(db):
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


def _make_group(authed_client, name):
    res = authed_client.post("/groups", json={"name": name, "description": "grp"})
    assert res.status_code == 201, res.text
    return res.json()


def _make_credential(authed_client, name):
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


def _add_system(authed_client, distro_id, group_id, cred_id, hostname, ip):
    res = authed_client.post(
        "/systems/add-system",
        json={
            "hostname": hostname,
            "ip_address": ip,
            "distro_id": distro_id,
            "status": "Active",
            "group_id": group_id,
            "credentials_id": cred_id,
            "environment": "Production",
        },
    )
    assert res.status_code == 201, res.text
    return res.json()


def test_systems_all_exposes_last_audited(authed_client, mock_vault, distro, db):
    group = _make_group(authed_client, "pra348-grp")
    cred = _make_credential(authed_client, "pra348-cred")
    _add_system(
        authed_client, distro.id, group["id"], cred["id"], "pra348-checked", "10.0.7.1"
    )
    _add_system(
        authed_client, distro.id, group["id"], cred["id"], "pra348-never", "10.0.7.2"
    )

    # Simulate a successful package scan stamping the durable last_audited.
    checked = db.query(System).filter_by(hostname="pra348-checked").one()
    checked.last_audited = datetime(2026, 8, 4, 21, 24, 56)
    db.commit()

    res = authed_client.get("/systems/all")
    assert res.status_code == 200, res.text
    by_host = {s["hostname"]: s for s in res.json()}

    # The scanned host exposes its timestamp; the never-scanned host is null.
    assert "last_audited" in by_host["pra348-checked"]
    assert by_host["pra348-checked"]["last_audited"] is not None
    assert by_host["pra348-checked"]["last_audited"].startswith("2026-08-04T21:24:56")
    assert by_host["pra348-never"]["last_audited"] is None
