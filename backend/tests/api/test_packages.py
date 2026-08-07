"""Integration tests for package update routes."""

from datetime import date
from unittest.mock import MagicMock

import pytest

from app.db.models import Distro, System


@pytest.fixture
def distro(db):
    """Local Distro fixture — conftest.distro uses non-existent columns."""
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


def _seed_system(db, distro, hostname="pkg-host", ip="10.0.1.10"):
    """Create a minimal system directly via ORM (bypass API) for package tests."""
    from app.db.models import Credential, Group

    group = db.query(Group).filter_by(name="pkg-group").first()
    if not group:
        group = Group(name="pkg-group", description="pkg tests")
        db.add(group)
        db.flush()

    cred = db.query(Credential).filter_by(name="pkg-cred").first()
    if not cred:
        cred = Credential(
            name="pkg-cred",
            auth_method="password",
            username="root",
            vault_path="praxis/credentials/pkg-cred",
            sudo_method="none",
        )
        db.add(cred)
        db.flush()

    sys_row = System(
        hostname=hostname,
        ip_address=ip,
        distro_id=distro.id,
        os_version=distro.version,
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    return sys_row


def test_list_all_updates_empty(authed_client):
    res = authed_client.get("/packages/updates/all")
    assert res.status_code == 200
    assert res.json() == []


def test_list_system_updates_empty(authed_client, db, distro):
    sys_row = _seed_system(db, distro, hostname="upd-host", ip="10.0.1.20")
    res = authed_client.get(f"/packages/updates/{sys_row.id}")
    assert res.status_code == 200
    assert res.json() == []


def test_list_system_updates_404(authed_client):
    res = authed_client.get("/packages/updates/999999")
    assert res.status_code == 404


def test_scan_packages_success(authed_client, db, distro, monkeypatch):
    """POST /packages/{system_id}/scan — verify success response shape."""
    sys_row = _seed_system(db, distro, hostname="scan2-host", ip="10.0.1.31")

    ssh_responses = [
        {
            "status": "success",
            "stdout": "bash\t5.1-6ubuntu1\tinstall ok installed\n",
            "stderr": "",
        },
        {
            "status": "success",
            "stdout": "",
            "stderr": "",
        },
    ]
    call_idx = {"i": 0}

    def fake_exec(self, system_id, command, timeout=60):
        i = call_idx["i"]
        call_idx["i"] += 1
        return ssh_responses[min(i, len(ssh_responses) - 1)]

    monkeypatch.setattr(
        "app.services.ssh_service.SSHService.execute_command", fake_exec
    )

    res = authed_client.post(f"/packages/{sys_row.id}/scan")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["system_id"] == sys_row.id
    assert body["hostname"] == "scan2-host"
    # packages_found reflects the one dpkg row parsed
    assert "packages_found" in body


def test_scan_packages_404_for_missing_system(authed_client):
    res = authed_client.post("/packages/999999/scan")
    assert res.status_code == 404
