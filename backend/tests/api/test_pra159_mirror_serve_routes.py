"""PRA-159 #2: GET /mirrors/{slug}/serve/{path:path} route tests.

Covers:
  * 200 with bytes when bearer is valid (Bearer + Basic forms)
  * 401 missing/invalid/cross-mirror bearer
  * 404 unknown mirror, soft-deleted mirror, missing file, traversal
  * last_used_at stamped on success
"""

from __future__ import annotations

import base64
from datetime import datetime
from pathlib import Path

import pytest

from app.db.models import (
    Credential,
    Group,
    HostMirrorServeCredential,
    MirrorRepo,
    System,
)
from app.services.mirror_serve_credential_service import MirrorServeCredentialService


@pytest.fixture
def mirror_root(tmp_path, monkeypatch) -> Path:
    """Override PRAXIS_MIRROR_ROOT to a tmp dir so tests can lay
    out a synthetic live/ tree without touching the real volume."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    return tmp_path


@pytest.fixture
def mirror(db) -> MirrorRepo:
    m = MirrorRepo(
        slug="serve-route-mirror",
        display_name="x",
        package_family="deb",
        upstream_url="http://x/y",
        distribution="jammy",
        components="[]",
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(m)
    db.commit()
    return m


@pytest.fixture
def other_mirror(db) -> MirrorRepo:
    m = MirrorRepo(
        slug="serve-route-other",
        display_name="x",
        package_family="deb",
        upstream_url="http://x/y",
        distribution="jammy",
        components="[]",
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(m)
    db.commit()
    return m


@pytest.fixture
def host(db, seed_distro) -> System:
    g = Group(name="serve-route-grp")
    db.add(g)
    db.flush()
    cred = Credential(name="serve-route-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    s = System(
        hostname="serve-route.example.com",
        ip_address="10.40.50.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.commit()
    return s


def _layout(mirror_root: Path, slug: str) -> Path:
    """Create <root>/<slug>/live/dists/jammy/Release with content."""
    live = mirror_root / slug / "live"
    (live / "dists" / "jammy").mkdir(parents=True, exist_ok=True)
    target = live / "dists" / "jammy" / "Release"
    target.write_bytes(b"Suite: jammy\nCodename: jammy\n")
    return target


def _bearer_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _basic_headers(token: str, user: str = "praxis") -> dict:
    raw = f"{user}:{token}".encode("utf-8")
    return {"Authorization": f"Basic {base64.b64encode(raw).decode('ascii')}"}


def test_serve_200_with_bearer(client, db, host, mirror, mirror_root):
    _layout(mirror_root, mirror.slug)
    issued = MirrorServeCredentialService(db).issue(
        host_id=host.id, mirror_id=mirror.id
    )
    res = client.get(
        f"/mirrors/{mirror.slug}/serve/dists/jammy/Release",
        headers=_bearer_headers(issued.plaintext),
    )
    assert res.status_code == 200, res.text
    assert b"Suite: jammy" in res.content


def test_serve_200_with_basic(client, db, host, mirror, mirror_root):
    _layout(mirror_root, mirror.slug)
    issued = MirrorServeCredentialService(db).issue(
        host_id=host.id, mirror_id=mirror.id
    )
    res = client.get(
        f"/mirrors/{mirror.slug}/serve/dists/jammy/Release",
        headers=_basic_headers(issued.plaintext),
    )
    assert res.status_code == 200
    assert b"Suite: jammy" in res.content


def test_serve_401_missing_auth(client, db, host, mirror, mirror_root):
    _layout(mirror_root, mirror.slug)
    res = client.get(f"/mirrors/{mirror.slug}/serve/dists/jammy/Release")
    # The serve path is allow-listed past JWT middleware so the
    # route's bearer challenge actually reaches the client; apt/dnf
    # clients see WWW-Authenticate: Bearer realm="praxis-mirror"
    # instead of the generic JWT 401 body.
    assert res.status_code == 401
    assert res.headers.get("WWW-Authenticate") == 'Bearer realm="praxis-mirror"'


def test_serve_401_basic_with_wrong_username(client, db, host, mirror, mirror_root):
    """Basic auth with a username other than ``praxis`` is rejected
    so generated host config that drifts to a different username
    fails fast instead of silently working.
    """
    _layout(mirror_root, mirror.slug)
    issued = MirrorServeCredentialService(db).issue(
        host_id=host.id, mirror_id=mirror.id
    )
    res = client.get(
        f"/mirrors/{mirror.slug}/serve/dists/jammy/Release",
        headers=_basic_headers(issued.plaintext, user="someone-else"),
    )
    assert res.status_code == 401


def test_serve_401_invalid_bearer(client, db, host, mirror, mirror_root):
    _layout(mirror_root, mirror.slug)
    res = client.get(
        f"/mirrors/{mirror.slug}/serve/dists/jammy/Release",
        headers=_bearer_headers("not-a-real-token-xxxx"),
    )
    assert res.status_code == 401


def test_serve_401_cross_mirror_bearer_rejected(
    client, db, host, mirror, other_mirror, mirror_root
):
    """A token issued for mirror A must NOT serve mirror B even if
    the bearer is otherwise valid."""
    _layout(mirror_root, mirror.slug)
    _layout(mirror_root, other_mirror.slug)
    issued = MirrorServeCredentialService(db).issue(
        host_id=host.id, mirror_id=mirror.id
    )
    res = client.get(
        f"/mirrors/{other_mirror.slug}/serve/dists/jammy/Release",
        headers=_bearer_headers(issued.plaintext),
    )
    assert res.status_code == 401


def test_serve_404_unknown_mirror(client, db, host, mirror_root):
    res = client.get(
        "/mirrors/no-such-mirror/serve/Release",
        headers=_bearer_headers("anything"),
    )
    assert res.status_code == 404


def test_serve_404_soft_deleted_mirror(client, db, host, mirror, mirror_root):
    _layout(mirror_root, mirror.slug)
    issued = MirrorServeCredentialService(db).issue(
        host_id=host.id, mirror_id=mirror.id
    )
    # Soft-delete mirror after issuing creds
    db.query(MirrorRepo).filter(MirrorRepo.id == mirror.id).update(
        {"deleted_at": datetime.utcnow()}
    )
    db.commit()
    res = client.get(
        f"/mirrors/{mirror.slug}/serve/dists/jammy/Release",
        headers=_bearer_headers(issued.plaintext),
    )
    assert res.status_code == 404


def test_serve_404_missing_file(client, db, host, mirror, mirror_root):
    _layout(mirror_root, mirror.slug)
    issued = MirrorServeCredentialService(db).issue(
        host_id=host.id, mirror_id=mirror.id
    )
    res = client.get(
        f"/mirrors/{mirror.slug}/serve/dists/jammy/NoSuchFile",
        headers=_bearer_headers(issued.plaintext),
    )
    assert res.status_code == 404


def test_serve_404_path_traversal_blocked(client, db, host, mirror, mirror_root):
    _layout(mirror_root, mirror.slug)
    # Place a sibling file *outside* live/ to confirm we'd otherwise
    # be able to read it if the guard failed.
    sibling = mirror_root / mirror.slug / "secret.txt"
    sibling.write_bytes(b"top-secret")
    issued = MirrorServeCredentialService(db).issue(
        host_id=host.id, mirror_id=mirror.id
    )
    # The literal "../" sequence is the most direct attack. The HTTP client
    # normalizes it, so the request that reaches the server is
    # ``/mirrors/<slug>/secret.txt`` — outside the ``/serve/`` namespace. Two
    # layers now deny it: (a) PRA-180 AUTH-01 made the JWT middleware fail
    # closed, so a non-serve ``/mirrors/...`` path presented with a serve
    # bearer (not a JWT) is rejected with 401 before routing; (b) if it did
    # reach the serve route, the realpath-prefix guard returns 404. Either
    # denial is correct — the secret must never be served.
    res = client.get(
        f"/mirrors/{mirror.slug}/serve/../secret.txt",
        headers=_bearer_headers(issued.plaintext),
    )
    assert res.status_code in (401, 404)
    assert res.status_code != 200


def test_serve_stamps_last_used_at(client, db, host, mirror, mirror_root):
    _layout(mirror_root, mirror.slug)
    issued = MirrorServeCredentialService(db).issue(
        host_id=host.id, mirror_id=mirror.id
    )
    res = client.get(
        f"/mirrors/{mirror.slug}/serve/dists/jammy/Release",
        headers=_bearer_headers(issued.plaintext),
    )
    assert res.status_code == 200
    row = (
        db.query(HostMirrorServeCredential)
        .filter(HostMirrorServeCredential.id == issued.credential_id)
        .one()
    )
    assert row.last_used_at is not None
