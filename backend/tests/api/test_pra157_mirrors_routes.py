"""PRA-157 #2b: mirror engine API route tests.

Covers CRUD on /mirrors, on-demand POST /{id}/sync (eligibility +
BackgroundTasks dispatch), GET /runs pagination, GET /manifest, and
soft-delete semantics (filtered from list, 404 from detail/sync,
bytes left on disk).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from unittest.mock import patch

from app.db.models import MirrorRepo, MirrorSyncRun


def _create_body(**overrides) -> dict:
    base = {
        "slug": "test-ubuntu-jammy",
        "display_name": "Test Ubuntu Jammy",
        "package_family": "deb",
        "upstream_url": "http://archive.ubuntu.com/ubuntu",
        "distribution": "jammy",
        "components": ["main", "universe"],
        "architectures": ["amd64"],
        "sync_schedule_cron": "0 2 * * *",
    }
    base.update(overrides)
    return base


def _post_create(client, **overrides):
    return client.post("/mirrors", json=_create_body(**overrides))


# ---------------------------------------------------------------------------
# CREATE
# ---------------------------------------------------------------------------


def test_create_mirror_minimum_fields_succeeds(authed_client):
    res = _post_create(authed_client)
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["slug"] == "test-ubuntu-jammy"
    assert body["package_family"] == "deb"
    assert body["components"] == ["main", "universe"]
    assert body["architectures"] == ["amd64"]
    assert body["enabled"] is True
    assert body["source_mode"] == "upstream_sync"
    assert body["last_sync_status"] == "idle"
    assert body["current_disk_bytes"] == 0


def test_create_mirror_duplicate_slug_409_or_400(authed_client):
    assert _post_create(authed_client).status_code == 201
    res = _post_create(authed_client, display_name="Duplicate slug")
    assert res.status_code == 400
    assert "already exists" in res.json()["detail"]


def test_create_mirror_rejects_invalid_cron(authed_client):
    res = _post_create(authed_client, sync_schedule_cron="not a cron")
    assert res.status_code == 422
    detail = json.dumps(res.json())
    assert "cron" in detail.lower()


def test_create_mirror_rejects_invalid_slug(authed_client):
    res = _post_create(authed_client, slug="HasUppercase")
    assert res.status_code == 422


def test_create_mirror_rejects_missing_architectures(authed_client):
    res = _post_create(authed_client, architectures=[])
    assert res.status_code == 422


def test_create_mirror_rejects_invalid_upstream_url(authed_client):
    res = _post_create(authed_client, upstream_url="not-a-url")
    assert res.status_code == 422


def test_create_mirror_rejects_negative_retention(authed_client):
    res = _post_create(authed_client, retention_keep_count=0)
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# LIST / GET / PATCH / DELETE
# ---------------------------------------------------------------------------


def test_list_mirrors_returns_created_and_excludes_soft_deleted(authed_client):
    a = _post_create(authed_client, slug="alpha").json()
    b = _post_create(authed_client, slug="beta").json()
    c = _post_create(authed_client, slug="charlie").json()

    res = authed_client.get("/mirrors")
    assert res.status_code == 200
    slugs = [m["slug"] for m in res.json()]
    assert "alpha" in slugs and "beta" in slugs and "charlie" in slugs

    # Soft-delete one — list shrinks.
    assert authed_client.delete(f"/mirrors/{b['id']}").status_code == 204
    slugs2 = [m["slug"] for m in authed_client.get("/mirrors").json()]
    assert "beta" not in slugs2
    assert "alpha" in slugs2 and "charlie" in slugs2


def test_get_mirror_detail_after_create(authed_client):
    created = _post_create(authed_client).json()
    res = authed_client.get(f"/mirrors/{created['id']}")
    assert res.status_code == 200
    assert res.json()["slug"] == created["slug"]


def test_get_mirror_404_after_soft_delete(authed_client):
    created = _post_create(authed_client).json()
    assert authed_client.delete(f"/mirrors/{created['id']}").status_code == 204
    res = authed_client.get(f"/mirrors/{created['id']}")
    assert res.status_code == 404


def test_patch_mirror_updates_fields(authed_client):
    created = _post_create(authed_client).json()
    res = authed_client.patch(
        f"/mirrors/{created['id']}",
        json={
            "display_name": "Renamed",
            "components": ["main", "universe", "multiverse"],
            "retention_keep_count": 25,
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert body["display_name"] == "Renamed"
    assert body["components"] == ["main", "universe", "multiverse"]
    assert body["retention_keep_count"] == 25


def test_patch_mirror_404_after_soft_delete(authed_client):
    created = _post_create(authed_client).json()
    authed_client.delete(f"/mirrors/{created['id']}")
    res = authed_client.patch(
        f"/mirrors/{created['id']}", json={"display_name": "anything"}
    )
    assert res.status_code == 404


def test_delete_mirror_is_soft(authed_client, db):
    created = _post_create(authed_client).json()
    assert authed_client.delete(f"/mirrors/{created['id']}").status_code == 204

    # Row still exists in DB with deleted_at set.
    row = db.query(MirrorRepo).filter(MirrorRepo.id == created["id"]).first()
    assert row is not None
    assert row.deleted_at is not None
    assert row.enabled is False


# ---------------------------------------------------------------------------
# POST /{id}/sync — eligibility + BackgroundTasks dispatch
# ---------------------------------------------------------------------------


def test_post_sync_dispatches_background_task(authed_client):
    created = _post_create(authed_client, slug="sync-target").json()
    with patch("app.api.routes.mirrors.claim_and_sync_one_mirror") as mock_claim:
        res = authed_client.post(f"/mirrors/{created['id']}/sync")

    assert res.status_code == 202
    body = res.json()
    assert body["queued"] is True
    assert body["mirror_repo_id"] == created["id"]
    # BackgroundTasks runs after response — TestClient drives it
    # synchronously, so by here the task should have been called.
    mock_claim.assert_called_once_with(created["id"], "sync-target")


def test_post_sync_refuses_imported_offline(authed_client):
    created = _post_create(authed_client, source_mode="imported_offline").json()
    res = authed_client.post(f"/mirrors/{created['id']}/sync")
    assert res.status_code == 409
    assert "imported_offline" in res.json()["detail"]


def test_post_sync_refuses_disabled(authed_client):
    created = _post_create(authed_client).json()
    authed_client.patch(f"/mirrors/{created['id']}", json={"enabled": False})
    res = authed_client.post(f"/mirrors/{created['id']}/sync")
    assert res.status_code == 409
    assert "disabled" in res.json()["detail"].lower()


def test_post_sync_refuses_when_already_running(authed_client, db):
    created = _post_create(authed_client).json()
    # Simulate an in-flight sync by setting last_sync_status='running'.
    row = db.query(MirrorRepo).filter(MirrorRepo.id == created["id"]).first()
    row.last_sync_status = "running"
    db.commit()

    res = authed_client.post(f"/mirrors/{created['id']}/sync")
    assert res.status_code == 409
    assert "in progress" in res.json()["detail"].lower()


def test_post_sync_404_for_soft_deleted(authed_client):
    created = _post_create(authed_client).json()
    authed_client.delete(f"/mirrors/{created['id']}")
    res = authed_client.post(f"/mirrors/{created['id']}/sync")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# GET /{id}/runs + GET /{id}/runs/{run_id}/manifest
# ---------------------------------------------------------------------------


def test_runs_endpoint_paginated(authed_client, db):
    created = _post_create(authed_client).json()
    base = datetime.utcnow() - timedelta(hours=10)
    db.add_all(
        [
            MirrorSyncRun(
                mirror_repo_id=created["id"],
                started_at=base + timedelta(minutes=i),
                status="ok",
                finished_at=base + timedelta(minutes=i, seconds=30),
                manifest_sha256="0" * 64,
                manifest_path="/tmp/whatever",
                byte_count=10,
                package_count=1,
            )
            for i in range(5)
        ]
    )
    db.commit()

    res = authed_client.get(f"/mirrors/{created['id']}/runs?limit=3")
    assert res.status_code == 200
    body = res.json()
    assert len(body) == 3
    # Newest first.
    assert body[0]["started_at"] > body[1]["started_at"]


def test_manifest_endpoint_404_for_failed_run(authed_client, db):
    created = _post_create(authed_client).json()
    failed = MirrorSyncRun(
        mirror_repo_id=created["id"],
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        status="failed",
        error_text="boom",
    )
    db.add(failed)
    db.commit()
    res = authed_client.get(f"/mirrors/{created['id']}/runs/{failed.id}/manifest")
    assert res.status_code == 404


def test_manifest_endpoint_410_when_file_missing(authed_client, db, tmp_path):
    """ok run row with manifest_path pointing at a file that's gone
    → 410 Gone (retention pruned the file but the row's still around).
    """
    created = _post_create(authed_client).json()
    ghost_path = str(tmp_path / "no-such-file.json")
    ok = MirrorSyncRun(
        mirror_repo_id=created["id"],
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        status="ok",
        manifest_sha256="0" * 64,
        manifest_path=ghost_path,
        byte_count=0,
        package_count=0,
    )
    db.add(ok)
    db.commit()
    res = authed_client.get(f"/mirrors/{created['id']}/runs/{ok.id}/manifest")
    assert res.status_code == 410


def test_manifest_endpoint_returns_json_when_file_present(authed_client, db, tmp_path):
    created = _post_create(authed_client).json()
    manifest_file = tmp_path / "real-manifest.json"
    manifest_payload = {"praxis_mirror_manifest": "v1", "files": []}
    manifest_file.write_text(json.dumps(manifest_payload))

    ok = MirrorSyncRun(
        mirror_repo_id=created["id"],
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        status="ok",
        manifest_sha256="0" * 64,
        manifest_path=str(manifest_file),
        byte_count=10,
        package_count=0,
    )
    db.add(ok)
    db.commit()

    res = authed_client.get(f"/mirrors/{created['id']}/runs/{ok.id}/manifest")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("application/json")
    assert res.json() == manifest_payload


def test_runs_endpoint_404_for_soft_deleted_mirror(authed_client):
    created = _post_create(authed_client).json()
    authed_client.delete(f"/mirrors/{created['id']}")
    res = authed_client.get(f"/mirrors/{created['id']}/runs")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# GET /{id}/runs/{run_id} — single-run lookup (PRA-157 #5-a)
# ---------------------------------------------------------------------------


def test_get_single_run_returns_manifest_sha256(authed_client, db):
    """The single-run endpoint exists so the manifest summary UI can
    render the run row's manifest_sha256 (the *content fingerprint*)
    alongside the manifest body's praxis_mirror_manifest (the
    *format version*) without paginating the full history.
    """
    created = _post_create(authed_client).json()
    run = MirrorSyncRun(
        mirror_repo_id=created["id"],
        started_at=datetime.utcnow() - timedelta(minutes=5),
        finished_at=datetime.utcnow(),
        status="ok",
        byte_count=42,
        package_count=1,
        manifest_sha256="abc" * 21 + "f",  # 64 chars
        manifest_path="/data/praxis/mirrors/example/snapshots/1.manifest.json",
    )
    db.add(run)
    db.commit()

    res = authed_client.get(f"/mirrors/{created['id']}/runs/{run.id}")
    assert res.status_code == 200
    body = res.json()
    assert body["id"] == run.id
    assert body["manifest_sha256"] == run.manifest_sha256
    assert body["status"] == "ok"


def test_get_single_run_404_for_missing_run(authed_client):
    created = _post_create(authed_client).json()
    res = authed_client.get(f"/mirrors/{created['id']}/runs/99999999")
    assert res.status_code == 404


def test_get_single_run_404_for_soft_deleted_mirror(authed_client):
    created = _post_create(authed_client).json()
    authed_client.delete(f"/mirrors/{created['id']}")
    res = authed_client.get(f"/mirrors/{created['id']}/runs/1")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# GET /{id}/browse — directory listing of live/ (PRA-157 #5)
# ---------------------------------------------------------------------------


def test_browse_404_when_no_live_tree(authed_client):
    """Mirror with no successful sync yet has no live/ — 404 with a
    helpful message rather than an opaque 500.
    """
    created = _post_create(authed_client, slug="browse-empty").json()
    res = authed_client.get(f"/mirrors/{created['id']}/browse")
    assert res.status_code == 404
    assert "no live/ tree yet" in res.json()["detail"].lower()


def test_browse_lists_root_entries(authed_client, tmp_path, monkeypatch):
    """List the live/ root for a mirror that has files on disk."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    created = _post_create(authed_client, slug="browse-root").json()

    live = tmp_path / "browse-root" / "live"
    live.mkdir(parents=True)
    (live / "Release").write_bytes(b"Origin: Praxis Test")
    pool = live / "pool" / "main"
    pool.mkdir(parents=True)
    (pool / "nginx_1.18.0_amd64.deb").write_bytes(b"fake-deb")

    res = authed_client.get(f"/mirrors/{created['id']}/browse")
    assert res.status_code == 200
    body = res.json()
    assert body["path"] == ""
    assert body["parent"] is None
    names = {e["name"] for e in body["entries"]}
    assert names == {"Release", "pool"}
    types = {e["name"]: e["type"] for e in body["entries"]}
    assert types["Release"] == "file"
    assert types["pool"] == "dir"


def test_browse_lists_nested_path(authed_client, tmp_path, monkeypatch):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    created = _post_create(authed_client, slug="browse-nested").json()

    live = tmp_path / "browse-nested" / "live"
    pool = live / "pool" / "main" / "n" / "nginx"
    pool.mkdir(parents=True)
    (pool / "nginx_1.18.0_amd64.deb").write_bytes(b"x" * 17)

    res = authed_client.get(f"/mirrors/{created['id']}/browse?path=pool/main/n/nginx")
    assert res.status_code == 200
    body = res.json()
    assert body["path"] == "pool/main/n/nginx"
    assert body["parent"] == "pool/main/n"
    assert body["entries"] == [
        {
            "name": "nginx_1.18.0_amd64.deb",
            "type": "file",
            "size": 17,
        }
    ]


def test_browse_rejects_path_traversal(authed_client, tmp_path, monkeypatch):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    created = _post_create(authed_client, slug="browse-traversal").json()
    (tmp_path / "browse-traversal" / "live").mkdir(parents=True)

    for bad in ("..", "../etc", "pool/../../../etc", "..\\windows", "\x00"):
        res = authed_client.get(
            f"/mirrors/{created['id']}/browse", params={"path": bad}
        )
        assert res.status_code == 400, (bad, res.text)


def test_browse_404_for_missing_subpath(authed_client, tmp_path, monkeypatch):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    created = _post_create(authed_client, slug="browse-missing").json()
    (tmp_path / "browse-missing" / "live").mkdir(parents=True)

    res = authed_client.get(f"/mirrors/{created['id']}/browse?path=pool/missing-dir")
    assert res.status_code == 404


def test_browse_404_for_soft_deleted_mirror(authed_client):
    created = _post_create(authed_client).json()
    authed_client.delete(f"/mirrors/{created['id']}")
    res = authed_client.get(f"/mirrors/{created['id']}/browse")
    assert res.status_code == 404


def test_browse_strips_leading_slash(authed_client, tmp_path, monkeypatch):
    """An accidental leading slash on the path query param is treated
    as relative — operators copying paths from manifests don't have
    to remember to strip it.
    """
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    created = _post_create(authed_client, slug="browse-leading-slash").json()
    live = tmp_path / "browse-leading-slash" / "live"
    sub = live / "pool"
    sub.mkdir(parents=True)
    (sub / "x.deb").write_bytes(b"")

    res = authed_client.get(
        f"/mirrors/{created['id']}/browse", params={"path": "/pool"}
    )
    assert res.status_code == 200
    assert res.json()["path"] == "pool"
