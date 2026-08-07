"""PRA-158 #3c: install-trust endpoint tests.

Mocks ``get_transport`` so the endpoint runs end-to-end against a fake
remote. Real transport layer is covered in PRA-153 tests; this file
asserts request-shape, RBAC, atomic 404 dispatch, partial-failure
overall_ok semantics, and host_mirror_trust persistence.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.db.models import (
    Credential,
    Group,
    HostMirrorTrust,
    MirrorRepo,
    MirrorSigningKey,
    System,
)
from app.services.mirror_signing_key_service import vault_path_for

_FPR = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"


def _add_key(db, mirror, *, status, fpr=_FPR):
    armored = f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-{fpr}\n-----END-----\n"
    row = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status=status,
        gpg_fingerprint=fpr,
        key_uid=f"Praxis Mirror Signing {mirror.slug} {fpr}",
        vault_path=vault_path_for(mirror.slug, fpr),
        armored_public_key=armored,
    )
    db.add(row)
    db.commit()
    return row


@pytest.fixture
def mirror(db) -> MirrorRepo:
    m = MirrorRepo(
        slug="install-test",
        display_name="Install Test",
        package_family="deb",
        upstream_url="http://example.com",
        distribution="jammy",
        components='["main"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


@pytest.fixture
def hosts(db, seed_distro):
    out = []
    for i in range(3):
        grp = Group(name=f"trust-grp-{i}", description="install test")
        db.add(grp)
        db.flush()
        cred = Credential(
            name=f"trust-cred-{i}", auth_method="ssh_key", username="root"
        )
        db.add(cred)
        db.flush()
        h = System(
            hostname=f"trust-host-{i}.example.com",
            ip_address=f"10.0.0.{i + 1}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=grp.id,
            credentials_id=cred.id,
        )
        db.add(h)
        out.append(h)
    db.commit()
    for h in out:
        db.refresh(h)
    return out


@pytest.fixture
def patch_transport(monkeypatch):
    """Replace get_transport with a factory returning a fake transport
    that always succeeds. Per-test variations override this.
    """

    def _make(success=True, transport_factory_fail=False):
        async def fake_get_transport(system, broker, ssh_service=None):
            if transport_factory_fail:
                raise RuntimeError("transport unavailable")
            t = MagicMock()
            t.name = "ssh"
            t.run_command = AsyncMock(
                return_value=MagicMock(
                    exit_code=0 if success else 1,
                    stderr=b"" if success else b"perm denied",
                    stdout=b"",
                )
            )
            return t

        # Patch the route's import-site, not the factory module — the
        # route binds a local name at import time.
        monkeypatch.setattr("app.api.routes.mirrors.get_transport", fake_get_transport)
        # Also stub BrokerClient + SSHService so the route doesn't try
        # to talk to real services.

        class _FakeBroker:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        monkeypatch.setattr(
            "app.api.routes.mirrors.BrokerClient", lambda: _FakeBroker()
        )
        monkeypatch.setattr("app.api.routes.mirrors.SSHService", lambda db: MagicMock())

    return _make


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_install_trust_writes_bundle_and_records_per_host(
    authed_client, db, mirror, hosts, patch_transport
):
    _add_key(db, mirror, status="active")
    patch_transport(success=True)

    res = authed_client.post(
        f"/mirrors/{mirror.id}/install-trust",
        json={"host_ids": [h.id for h in hosts]},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["mirror_id"] == mirror.id
    assert body["ok"] is True
    assert len(body["results"]) == 3
    for r in body["results"]:
        assert r["ok"] is True
        assert r["installed_fingerprints"] == [_FPR]
        assert r["written_paths"] == [
            "/etc/apt/keyrings/praxis-mirror-install-test.asc"
        ]

    # host_mirror_trust upserted for each host.
    rows = db.query(HostMirrorTrust).filter_by(mirror_id=mirror.id).all()
    assert len(rows) == 3
    for row in rows:
        assert row.installed_fingerprints == [_FPR]
        assert isinstance(row.last_installed_at, datetime)


# ---------------------------------------------------------------------------
# Validation + 404 atomicity
# ---------------------------------------------------------------------------


def test_install_trust_400_on_empty_host_ids(authed_client, mirror, patch_transport):
    patch_transport(success=True)
    res = authed_client.post(
        f"/mirrors/{mirror.id}/install-trust", json={"host_ids": []}
    )
    assert res.status_code == 400


def test_install_trust_404_on_missing_mirror(authed_client, hosts, patch_transport):
    patch_transport(success=True)
    res = authed_client.post(
        "/mirrors/99999/install-trust",
        json={"host_ids": [hosts[0].id]},
    )
    assert res.status_code == 404


def test_install_trust_404_on_unknown_host_aborts_atomically(
    authed_client, db, mirror, hosts, patch_transport
):
    """Atomic dispatch: an unknown host_id must 404 BEFORE any host
    receives a write. Otherwise an operator's typo could half-deploy
    a key set across the fleet.
    """
    _add_key(db, mirror, status="active")
    patch_transport(success=True)

    res = authed_client.post(
        f"/mirrors/{mirror.id}/install-trust",
        json={"host_ids": [hosts[0].id, 99999, hosts[1].id]},
    )
    assert res.status_code == 404
    # No host_mirror_trust row should exist for any host.
    assert db.query(HostMirrorTrust).filter_by(mirror_id=mirror.id).count() == 0


# ---------------------------------------------------------------------------
# Partial failure
# ---------------------------------------------------------------------------


def test_install_trust_partial_failure_marks_overall_not_ok(
    authed_client, db, mirror, hosts, patch_transport
):
    """If one host fails (e.g. transport setup blew up), overall_ok=False
    but per-host detail tells the operator which hosts succeeded.
    """
    _add_key(db, mirror, status="active")

    # Custom transport: first host succeeds, second fails at transport
    # construction, third succeeds. Use call counter to discriminate.
    call_count = {"n": 0}

    async def fake_get_transport(system, broker, ssh_service=None):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise RuntimeError("agent down for host 2")
        t = MagicMock()
        t.name = "ssh"
        t.run_command = AsyncMock(
            return_value=MagicMock(exit_code=0, stderr=b"", stdout=b"")
        )
        return t

    import app.api.routes.mirrors as routes_mod

    class _FakeBroker:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    routes_mod.get_transport = fake_get_transport
    routes_mod.BrokerClient = lambda: _FakeBroker()
    routes_mod.SSHService = lambda db: MagicMock()

    res = authed_client.post(
        f"/mirrors/{mirror.id}/install-trust",
        json={"host_ids": [h.id for h in hosts]},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is False  # partial failure
    statuses = {r["host_id"]: r["ok"] for r in body["results"]}
    assert statuses[hosts[0].id] is True
    assert statuses[hosts[1].id] is False
    assert statuses[hosts[2].id] is True


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


def test_install_trust_403_for_auditor(
    client, db, mirror, hosts, seed_roles, patch_transport
):
    _add_key(db, mirror, status="active")
    patch_transport(success=True)

    from app.core.auth import get_password_hash
    from app.db.models import User

    auditor = User(
        username="trust-auditor",
        email="trust-auditor@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    auditor.roles.append(seed_roles["auditor"])
    db.add(auditor)
    db.commit()

    login = client.post(
        "/auth/login", data={"username": "trust-auditor", "password": "testpass123"}
    )
    token = login.json()["access_token"]
    res = client.post(
        f"/mirrors/{mirror.id}/install-trust",
        headers={"Authorization": f"Bearer {token}"},
        json={"host_ids": [hosts[0].id]},
    )
    assert res.status_code == 403
