"""PRA-159 #1: content channel CRUD + repo sub-resource route tests.

Covers:
  * POST/GET/PATCH/DELETE /content-channels
  * Slug uniqueness, slug/family validation, soft-delete semantics
  * POST /content-channels/{id}/repos with package_family + pin
    validation
  * Triple-uniqueness + inherit-suite partial-unique constraints
  * Refusal to soft-delete a channel composed by a profile
  * PATCH .../repos/{id}/pin
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.db.models import (
    ContentChannel,
    ContentChannelRepo,
    ContentProfile,
    ContentProfileChannel,
    MirrorRepo,
    MirrorSyncRun,
)


@pytest.fixture
def deb_mirror(db) -> MirrorRepo:
    mirror = MirrorRepo(
        slug="ubuntu-jammy",
        display_name="Ubuntu Jammy",
        package_family="deb",
        upstream_url="http://archive.ubuntu.com/ubuntu",
        distribution="jammy",
        components='["main","universe"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(mirror)
    db.flush()
    db.commit()
    return mirror


@pytest.fixture
def rpm_mirror(db) -> MirrorRepo:
    mirror = MirrorRepo(
        slug="rocky9-baseos",
        display_name="Rocky 9 BaseOS",
        package_family="rpm",
        upstream_url="http://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os",
        distribution="9",
        components="[]",
        architectures='["x86_64"]',
        sync_schedule_cron="0 3 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(mirror)
    db.flush()
    db.commit()
    return mirror


@pytest.fixture
def deb_ok_run(db, deb_mirror) -> MirrorSyncRun:
    run = MirrorSyncRun(
        mirror_repo_id=deb_mirror.id,
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        status="ok",
        run_kind="sync",
        manifest_sha256="a" * 64,
        manifest_path="/data/snapshots/run-1.manifest.json",
        byte_count=12345,
        package_count=42,
    )
    db.add(run)
    db.flush()
    db.commit()
    return run


def _channel_body(**overrides) -> dict:
    base = {
        "slug": "prod-ubuntu-22-04",
        "display_name": "Prod Ubuntu 22.04",
        "package_family": "deb",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# CREATE / GET / LIST
# ---------------------------------------------------------------------------


def test_create_channel_minimum_fields(authed_client):
    res = authed_client.post("/content-channels", json=_channel_body())
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["slug"] == "prod-ubuntu-22-04"
    assert body["package_family"] == "deb"
    assert body["repos"] == []
    assert body["deleted_at"] is None


def test_create_channel_duplicate_slug_400(authed_client):
    assert (
        authed_client.post("/content-channels", json=_channel_body()).status_code == 201
    )
    res = authed_client.post(
        "/content-channels", json=_channel_body(display_name="Other")
    )
    assert res.status_code == 400
    assert "already exists" in res.json()["detail"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("slug", "Has-Upper"),
        ("slug", ""),
        ("slug", "bad slug"),
        ("display_name", ""),
        ("package_family", "snap"),
        ("description", "x" * 5000),
    ],
)
def test_create_channel_validation_rejects_bad_input(authed_client, field, value):
    res = authed_client.post("/content-channels", json=_channel_body(**{field: value}))
    assert res.status_code == 422, res.text


def test_list_channels_default_excludes_soft_deleted(authed_client, db):
    a = authed_client.post("/content-channels", json=_channel_body(slug="alpha")).json()
    b = authed_client.post("/content-channels", json=_channel_body(slug="beta")).json()
    # Soft-delete b directly
    db.query(ContentChannel).filter(ContentChannel.id == b["id"]).update(
        {"deleted_at": datetime.utcnow()}
    )
    db.commit()

    visible = {c["slug"] for c in authed_client.get("/content-channels").json()}
    assert visible == {"alpha"}

    with_deleted = {
        c["slug"]
        for c in authed_client.get("/content-channels?include_deleted=true").json()
    }
    assert with_deleted == {"alpha", "beta"}


def test_get_channel_404_on_unknown_id(authed_client):
    assert authed_client.get("/content-channels/9999").status_code == 404


def test_patch_channel_updates_display_name(authed_client):
    created = authed_client.post("/content-channels", json=_channel_body()).json()
    res = authed_client.patch(
        f"/content-channels/{created['id']}", json={"display_name": "Renamed"}
    )
    assert res.status_code == 200
    assert res.json()["display_name"] == "Renamed"


def test_patch_channel_silently_ignores_immutable_slug(authed_client):
    """``slug`` isn't on ``ContentChannelUpdate``, so Pydantic drops it.

    The PATCH succeeds without renaming — important so an operator
    sending the full read shape back doesn't get an unexpected 422.
    """
    created = authed_client.post("/content-channels", json=_channel_body()).json()
    res = authed_client.patch(
        f"/content-channels/{created['id']}",
        json={"slug": "renamed-slug", "display_name": "Renamed"},
    )
    assert res.status_code == 200
    assert res.json()["slug"] == created["slug"]
    assert res.json()["display_name"] == "Renamed"


def test_delete_channel_soft_marks_and_removes_from_default_list(authed_client):
    created = authed_client.post("/content-channels", json=_channel_body()).json()
    assert authed_client.delete(f"/content-channels/{created['id']}").status_code == 204
    assert created["slug"] not in {
        c["slug"] for c in authed_client.get("/content-channels").json()
    }
    # Default detail mirrors list semantics — soft-deleted is hidden.
    assert authed_client.get(f"/content-channels/{created['id']}").status_code == 404
    # Tombstone read requires explicit ?include_deleted=true.
    detail = authed_client.get(
        f"/content-channels/{created['id']}?include_deleted=true"
    ).json()
    assert detail["deleted_at"] is not None


def test_delete_channel_refused_if_in_use_by_profile(authed_client, db):
    channel = authed_client.post("/content-channels", json=_channel_body()).json()
    profile = authed_client.post(
        "/content-profiles",
        json={
            "slug": "my-profile",
            "display_name": "My Profile",
            "package_family": "deb",
        },
    ).json()
    res = authed_client.post(
        f"/content-profiles/{profile['id']}/channels",
        json={"channel_id": channel["id"]},
    )
    assert res.status_code == 201

    res = authed_client.delete(f"/content-channels/{channel['id']}")
    assert res.status_code == 409
    assert "compose" in res.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Repo sub-resource
# ---------------------------------------------------------------------------


def test_add_repo_inherits_suite_when_override_omitted(authed_client, deb_mirror):
    channel = authed_client.post("/content-channels", json=_channel_body()).json()
    res = authed_client.post(
        f"/content-channels/{channel['id']}/repos",
        json={"mirror_id": deb_mirror.id},
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["suite_override"] is None
    assert body["effective_suite"] == "jammy"
    assert body["mirror_slug"] == "ubuntu-jammy"
    assert body["pinned_run_id"] is None


def test_add_repo_with_suite_override(authed_client, deb_mirror):
    channel = authed_client.post("/content-channels", json=_channel_body()).json()
    res = authed_client.post(
        f"/content-channels/{channel['id']}/repos",
        json={"mirror_id": deb_mirror.id, "suite_override": "jammy-security"},
    )
    assert res.status_code == 201
    assert res.json()["effective_suite"] == "jammy-security"


def test_add_repo_rejects_family_mismatch(authed_client, rpm_mirror):
    channel = authed_client.post(
        "/content-channels", json=_channel_body(slug="deb-c", package_family="deb")
    ).json()
    res = authed_client.post(
        f"/content-channels/{channel['id']}/repos",
        json={"mirror_id": rpm_mirror.id},
    )
    assert res.status_code == 400
    assert "package_family" in res.json()["detail"]


def test_add_repo_rejects_unknown_mirror(authed_client):
    channel = authed_client.post("/content-channels", json=_channel_body()).json()
    res = authed_client.post(
        f"/content-channels/{channel['id']}/repos", json={"mirror_id": 99999}
    )
    assert res.status_code == 400


def test_add_repo_rejects_duplicate_inherit_suite(authed_client, deb_mirror):
    channel = authed_client.post("/content-channels", json=_channel_body()).json()
    first = authed_client.post(
        f"/content-channels/{channel['id']}/repos",
        json={"mirror_id": deb_mirror.id},
    )
    assert first.status_code == 201
    second = authed_client.post(
        f"/content-channels/{channel['id']}/repos",
        json={"mirror_id": deb_mirror.id},
    )
    assert second.status_code == 409


def test_add_repo_allows_multi_suite_composition(authed_client, deb_mirror):
    channel = authed_client.post("/content-channels", json=_channel_body()).json()
    for suite in ("jammy", "jammy-security", "jammy-updates"):
        res = authed_client.post(
            f"/content-channels/{channel['id']}/repos",
            json={"mirror_id": deb_mirror.id, "suite_override": suite},
        )
        assert res.status_code == 201, (suite, res.text)
    detail = authed_client.get(f"/content-channels/{channel['id']}").json()
    assert sorted(r["effective_suite"] for r in detail["repos"]) == sorted(
        ["jammy", "jammy-security", "jammy-updates"]
    )


def test_add_repo_with_valid_pinned_run(authed_client, deb_mirror, deb_ok_run):
    channel = authed_client.post("/content-channels", json=_channel_body()).json()
    res = authed_client.post(
        f"/content-channels/{channel['id']}/repos",
        json={"mirror_id": deb_mirror.id, "pinned_run_id": deb_ok_run.id},
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["pinned_run_id"] == deb_ok_run.id
    assert body["pinned_manifest_sha256"] == "a" * 64


def test_add_repo_rejects_pinned_run_from_other_mirror(
    authed_client, deb_mirror, rpm_mirror, deb_ok_run
):
    """Pin must reference a run on the same mirror."""
    other = authed_client.post(
        "/content-channels",
        json=_channel_body(slug="rpm-channel", package_family="rpm"),
    ).json()
    res = authed_client.post(
        f"/content-channels/{other['id']}/repos",
        json={"mirror_id": rpm_mirror.id, "pinned_run_id": deb_ok_run.id},
    )
    assert res.status_code == 400
    assert "belongs to mirror" in res.json()["detail"]


def test_add_repo_rejects_pinned_run_with_failed_status(authed_client, db, deb_mirror):
    failed = MirrorSyncRun(
        mirror_repo_id=deb_mirror.id,
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        status="failed",
        run_kind="sync",
        error_text="upstream signature invalid",
    )
    db.add(failed)
    db.commit()

    channel = authed_client.post("/content-channels", json=_channel_body()).json()
    res = authed_client.post(
        f"/content-channels/{channel['id']}/repos",
        json={"mirror_id": deb_mirror.id, "pinned_run_id": failed.id},
    )
    assert res.status_code == 400
    assert "status='failed'" in res.json()["detail"] or "ok" in res.json()["detail"]


def test_patch_repo_pin_to_null_clears_pin(authed_client, deb_mirror, deb_ok_run):
    channel = authed_client.post("/content-channels", json=_channel_body()).json()
    repo = authed_client.post(
        f"/content-channels/{channel['id']}/repos",
        json={"mirror_id": deb_mirror.id, "pinned_run_id": deb_ok_run.id},
    ).json()
    res = authed_client.patch(
        f"/content-channels/{channel['id']}/repos/{repo['id']}/pin",
        json={"pinned_run_id": None},
    )
    assert res.status_code == 200
    assert res.json()["pinned_run_id"] is None


def test_remove_repo_204(authed_client, db, deb_mirror):
    channel = authed_client.post("/content-channels", json=_channel_body()).json()
    repo = authed_client.post(
        f"/content-channels/{channel['id']}/repos",
        json={"mirror_id": deb_mirror.id},
    ).json()
    res = authed_client.delete(f"/content-channels/{channel['id']}/repos/{repo['id']}")
    assert res.status_code == 204
    assert (
        db.query(ContentChannelRepo).filter(ContentChannelRepo.id == repo["id"]).first()
        is None
    )


def test_remove_repo_404_when_belongs_to_another_channel(authed_client, deb_mirror):
    a = authed_client.post("/content-channels", json=_channel_body(slug="a")).json()
    b = authed_client.post("/content-channels", json=_channel_body(slug="b")).json()
    repo = authed_client.post(
        f"/content-channels/{a['id']}/repos",
        json={"mirror_id": deb_mirror.id},
    ).json()
    res = authed_client.delete(f"/content-channels/{b['id']}/repos/{repo['id']}")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# AuthZ
# ---------------------------------------------------------------------------


def test_create_channel_requires_admin_or_maintainer(client, db, seed_roles):
    """Auditor (read-only role) cannot create channels."""
    from app.core.auth import get_password_hash
    from app.db.models import User

    auditor = User(
        username="aud-pra159",
        email="aud@x",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    auditor.roles.append(seed_roles["auditor"])
    db.add(auditor)
    db.commit()

    res = client.post(
        "/auth/login", data={"username": "aud-pra159", "password": "testpass123"}
    )
    token = res.json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {token}"})

    res = client.post("/content-channels", json=_channel_body())
    assert res.status_code == 403
