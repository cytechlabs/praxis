"""PRA-159 #2: route tests for /content-profiles/{id}/{resolved,manifest,diff}
+ /systems/{id}/content-profile/resolved + mirror-serve-credentials CRUD.
"""

from __future__ import annotations

import pytest

from app.db.models import (
    Credential,
    Group,
    HostContentProfileSubscription,
    MirrorRepo,
    System,
)


@pytest.fixture
def deb_mirror(db) -> MirrorRepo:
    m = MirrorRepo(
        slug="resolve-mirror",
        display_name="x",
        package_family="deb",
        upstream_url="http://x/y",
        distribution="jammy",
        components='["main"]',
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
    g = Group(name="resolve-rt-grp")
    db.add(g)
    db.flush()
    cred = Credential(name="resolve-rt-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    s = System(
        hostname="resolve-rt.example.com",
        ip_address="10.60.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.commit()
    return s


def _make_profile_with_repo(authed_client, deb_mirror, profile_slug):
    chan = authed_client.post(
        "/content-channels",
        json={
            "slug": f"chan-{profile_slug}",
            "display_name": "x",
            "package_family": "deb",
        },
    ).json()
    authed_client.post(
        f"/content-channels/{chan['id']}/repos",
        json={"mirror_id": deb_mirror.id},
    )
    profile = authed_client.post(
        "/content-profiles",
        json={
            "slug": profile_slug,
            "display_name": "x",
            "package_family": "deb",
        },
    ).json()
    authed_client.post(
        f"/content-profiles/{profile['id']}/channels",
        json={"channel_id": chan["id"]},
    )
    return profile, chan


def test_get_profile_resolved_returns_entries(authed_client, deb_mirror):
    profile, chan = _make_profile_with_repo(authed_client, deb_mirror, "rp-route-1")
    res = authed_client.get(f"/content-profiles/{profile['id']}/resolved")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["state"] == "resolved"
    assert body["profile"]["profile_slug"] == "rp-route-1"
    assert len(body["entries"]) == 1
    e = body["entries"][0]
    assert e["mirror_slug"] == "resolve-mirror"
    assert e["suite"] == "jammy"
    assert e["pinned_run_id"] is None


def test_get_profile_resolved_404_unknown(authed_client):
    assert authed_client.get("/content-profiles/9999/resolved").status_code == 404


def test_get_profile_manifest_empty_when_no_runs(authed_client, deb_mirror):
    profile, _ = _make_profile_with_repo(authed_client, deb_mirror, "rp-manif-1")
    res = authed_client.get(f"/content-profiles/{profile['id']}/manifest")
    assert res.status_code == 200
    body = res.json()
    assert body["packages"] == []
    assert body["summary"]["package_count"] == 0
    assert body["summary"]["entry_count"] == 1


def test_get_profile_diff_same_profile_400(authed_client, deb_mirror):
    profile, _ = _make_profile_with_repo(authed_client, deb_mirror, "rp-diff-self")
    res = authed_client.get(
        f"/content-profiles/{profile['id']}/diff",
        params={"from_profile_id": profile["id"]},
    )
    assert res.status_code == 400


def test_get_profile_diff_two_empty_profiles(authed_client, deb_mirror):
    a, _ = _make_profile_with_repo(authed_client, deb_mirror, "rp-diff-a")
    b, _ = _make_profile_with_repo(authed_client, deb_mirror, "rp-diff-b")
    res = authed_client.get(
        f"/content-profiles/{b['id']}/diff",
        params={"from_profile_id": a["id"]},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["added"] == []
    assert body["removed"] == []
    assert body["changed"] == []


def test_host_resolved_no_profile_state(authed_client, host):
    res = authed_client.get(f"/systems/{host.id}/content-profile/resolved")
    assert res.status_code == 200
    body = res.json()
    assert body["state"] == "no_profile"
    assert body["entries"] == []


def test_host_resolved_resolved_state_lists_entries(
    authed_client, db, host, deb_mirror
):
    profile, _ = _make_profile_with_repo(authed_client, deb_mirror, "rp-host-resolved")
    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=profile["id"]))
    db.commit()
    res = authed_client.get(f"/systems/{host.id}/content-profile/resolved")
    assert res.status_code == 200
    body = res.json()
    assert body["state"] == "resolved"
    assert len(body["entries"]) == 1
    assert body["profile"]["profile_slug"] == "rp-host-resolved"


def test_host_resolved_404_unknown_system(authed_client):
    assert (
        authed_client.get("/systems/99999/content-profile/resolved").status_code == 404
    )


# ---------------------------------------------------------------------------
# mirror-serve-credentials CRUD
# ---------------------------------------------------------------------------


def test_issue_credential_returns_plaintext_once(authed_client, host, deb_mirror):
    res = authed_client.post(
        f"/systems/{host.id}/mirror-serve-credentials",
        json={"mirror_id": deb_mirror.id},
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["host_id"] == host.id
    assert body["mirror_id"] == deb_mirror.id
    assert body["plaintext"]


def test_list_credentials_no_plaintext(authed_client, host, deb_mirror):
    issued = authed_client.post(
        f"/systems/{host.id}/mirror-serve-credentials",
        json={"mirror_id": deb_mirror.id},
    ).json()
    rows = authed_client.get(f"/systems/{host.id}/mirror-serve-credentials").json()
    assert len(rows) == 1
    assert rows[0]["id"] == issued["credential_id"]
    assert "plaintext" not in rows[0]
    assert "token_hash" not in rows[0]
    assert rows[0]["mirror_slug"] == deb_mirror.slug


def test_revoke_credential_204_then_404(authed_client, host, deb_mirror):
    issued = authed_client.post(
        f"/systems/{host.id}/mirror-serve-credentials",
        json={"mirror_id": deb_mirror.id},
    ).json()
    res = authed_client.delete(
        f"/systems/{host.id}/mirror-serve-credentials/{issued['credential_id']}"
    )
    assert res.status_code == 204
    again = authed_client.delete(
        f"/systems/{host.id}/mirror-serve-credentials/{issued['credential_id']}"
    )
    assert again.status_code == 404


def test_issue_credential_requires_admin_or_maintainer(
    client, db, seed_roles, host, deb_mirror
):
    """Auditor (read-only) can list but cannot issue."""
    from app.core.auth import get_password_hash
    from app.db.models import User

    auditor = User(
        username="aud-pra159-cred",
        email="aud@x",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    auditor.roles.append(seed_roles["auditor"])
    db.add(auditor)
    db.commit()

    res = client.post(
        "/auth/login",
        data={"username": "aud-pra159-cred", "password": "testpass123"},
    )
    token = res.json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {token}"})

    res = client.post(
        f"/systems/{host.id}/mirror-serve-credentials",
        json={"mirror_id": deb_mirror.id},
    )
    assert res.status_code == 403


def test_list_credentials_404_unknown_system(authed_client):
    assert (
        authed_client.get("/systems/99999/mirror-serve-credentials").status_code == 404
    )
