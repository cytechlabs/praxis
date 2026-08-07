"""PRA-159 #1: content profile CRUD + channel link + subscriptions
+ effective resolution route tests.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.db.models import (
    ContentChannel,
    ContentProfile,
    Credential,
    Group,
    HostContentProfileSubscription,
    MirrorRepo,
    SmartGroup,
    SmartGroupMembership,
    System,
)


@pytest.fixture
def deb_mirror(db) -> MirrorRepo:
    mirror = MirrorRepo(
        slug="ubuntu-jammy-prof",
        display_name="Ubuntu Jammy",
        package_family="deb",
        upstream_url="http://archive.ubuntu.com/ubuntu",
        distribution="jammy",
        components='["main"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(mirror)
    db.commit()
    return mirror


@pytest.fixture
def deb_channel(authed_client, db, deb_mirror) -> dict:
    channel = authed_client.post(
        "/content-channels",
        json={
            "slug": "deb-channel",
            "display_name": "Deb Channel",
            "package_family": "deb",
        },
    ).json()
    authed_client.post(
        f"/content-channels/{channel['id']}/repos",
        json={"mirror_id": deb_mirror.id},
    )
    return channel


@pytest.fixture
def host_with_group(db, seed_distro) -> System:
    g = Group(name="pra159-hosts")
    db.add(g)
    db.flush()
    cred = Credential(name="cred-pra159", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    s = System(
        hostname="host-pra159.example.com",
        ip_address="10.20.30.40",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.commit()
    return s


def _profile_body(**overrides) -> dict:
    base = {
        "slug": "prod-deb",
        "display_name": "Prod Deb",
        "package_family": "deb",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Profile CRUD
# ---------------------------------------------------------------------------


def test_create_profile_succeeds(authed_client):
    res = authed_client.post("/content-profiles", json=_profile_body())
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["slug"] == "prod-deb"
    assert body["channels"] == []


def test_create_profile_duplicate_slug(authed_client):
    assert (
        authed_client.post("/content-profiles", json=_profile_body()).status_code == 201
    )
    res = authed_client.post(
        "/content-profiles", json=_profile_body(display_name="Dup")
    )
    assert res.status_code == 400


def test_list_profiles_excludes_soft_deleted(authed_client, db):
    a = authed_client.post("/content-profiles", json=_profile_body(slug="alpha")).json()
    b = authed_client.post("/content-profiles", json=_profile_body(slug="beta")).json()
    db.query(ContentProfile).filter(ContentProfile.id == b["id"]).update(
        {"deleted_at": datetime.utcnow()}
    )
    db.commit()

    visible = {p["slug"] for p in authed_client.get("/content-profiles").json()}
    assert visible == {"alpha"}


def test_patch_profile_updates_display_name(authed_client):
    p = authed_client.post("/content-profiles", json=_profile_body()).json()
    res = authed_client.patch(
        f"/content-profiles/{p['id']}", json={"display_name": "Renamed"}
    )
    assert res.status_code == 200
    assert res.json()["display_name"] == "Renamed"


def test_delete_profile_soft(authed_client, db):
    p = authed_client.post("/content-profiles", json=_profile_body()).json()
    assert authed_client.delete(f"/content-profiles/{p['id']}").status_code == 204
    # Default detail mirrors list semantics — soft-deleted is hidden.
    assert authed_client.get(f"/content-profiles/{p['id']}").status_code == 404
    # Tombstone read requires explicit ?include_deleted=true.
    detail = authed_client.get(
        f"/content-profiles/{p['id']}?include_deleted=true"
    ).json()
    assert detail["deleted_at"] is not None


# ---------------------------------------------------------------------------
# Profile↔channel composition
# ---------------------------------------------------------------------------


def test_add_channel_to_profile(authed_client, deb_channel):
    p = authed_client.post("/content-profiles", json=_profile_body()).json()
    res = authed_client.post(
        f"/content-profiles/{p['id']}/channels",
        json={"channel_id": deb_channel["id"]},
    )
    assert res.status_code == 201
    body = res.json()
    assert len(body["channels"]) == 1
    assert body["channels"][0]["channel_slug"] == "deb-channel"


def test_add_channel_rejects_family_mismatch(authed_client, db, deb_channel):
    p = authed_client.post(
        "/content-profiles",
        json=_profile_body(slug="rpm-prof", package_family="rpm"),
    ).json()
    res = authed_client.post(
        f"/content-profiles/{p['id']}/channels",
        json={"channel_id": deb_channel["id"]},
    )
    assert res.status_code == 400
    assert "package_family" in res.json()["detail"]


def test_add_channel_rejects_unknown_channel(authed_client):
    p = authed_client.post("/content-profiles", json=_profile_body()).json()
    res = authed_client.post(
        f"/content-profiles/{p['id']}/channels", json={"channel_id": 99999}
    )
    assert res.status_code == 400


def test_add_channel_duplicate_409(authed_client, deb_channel):
    p = authed_client.post("/content-profiles", json=_profile_body()).json()
    first = authed_client.post(
        f"/content-profiles/{p['id']}/channels",
        json={"channel_id": deb_channel["id"]},
    )
    assert first.status_code == 201
    second = authed_client.post(
        f"/content-profiles/{p['id']}/channels",
        json={"channel_id": deb_channel["id"]},
    )
    assert second.status_code == 409


def test_remove_channel_from_profile(authed_client, deb_channel):
    p = authed_client.post("/content-profiles", json=_profile_body()).json()
    authed_client.post(
        f"/content-profiles/{p['id']}/channels",
        json={"channel_id": deb_channel["id"]},
    )
    res = authed_client.delete(
        f"/content-profiles/{p['id']}/channels/{deb_channel['id']}"
    )
    assert res.status_code == 204
    detail = authed_client.get(f"/content-profiles/{p['id']}").json()
    assert detail["channels"] == []


# ---------------------------------------------------------------------------
# Subscriptions
# ---------------------------------------------------------------------------


def test_subscribe_host_directly(authed_client, host_with_group):
    p = authed_client.post("/content-profiles", json=_profile_body()).json()
    res = authed_client.post(
        f"/content-profiles/{p['id']}/hosts",
        json={"host_id": host_with_group.id},
    )
    assert res.status_code == 201
    body = res.json()
    assert body["scope_kind"] == "host"
    assert body["scope_id"] == host_with_group.id
    assert body["scope_label"] == host_with_group.hostname


def test_subscribe_host_duplicate_409(authed_client, host_with_group):
    p = authed_client.post("/content-profiles", json=_profile_body()).json()
    first = authed_client.post(
        f"/content-profiles/{p['id']}/hosts",
        json={"host_id": host_with_group.id},
    )
    assert first.status_code == 201
    second = authed_client.post(
        f"/content-profiles/{p['id']}/hosts",
        json={"host_id": host_with_group.id},
    )
    assert second.status_code == 409


def test_unsubscribe_host(authed_client, host_with_group):
    p = authed_client.post("/content-profiles", json=_profile_body()).json()
    authed_client.post(
        f"/content-profiles/{p['id']}/hosts",
        json={"host_id": host_with_group.id},
    )
    res = authed_client.delete(
        f"/content-profiles/{p['id']}/hosts/{host_with_group.id}"
    )
    assert res.status_code == 204


def test_subscribe_group(authed_client, host_with_group):
    p = authed_client.post("/content-profiles", json=_profile_body()).json()
    res = authed_client.post(
        f"/content-profiles/{p['id']}/groups",
        json={"group_id": host_with_group.group_id},
    )
    assert res.status_code == 201
    assert res.json()["scope_kind"] == "group"


def test_subscribe_smart_group(authed_client, db):
    sg = SmartGroup(name="pra159-sg", rule_json='{"op":"and","rules":[]}')
    db.add(sg)
    db.commit()
    p = authed_client.post("/content-profiles", json=_profile_body()).json()
    res = authed_client.post(
        f"/content-profiles/{p['id']}/smart-groups",
        json={"smart_group_id": sg.id},
    )
    assert res.status_code == 201
    assert res.json()["scope_kind"] == "smart_group"


def test_list_subscriptions_returns_all_three_kinds(authed_client, db, host_with_group):
    sg = SmartGroup(name="pra159-list-sg", rule_json='{"op":"and","rules":[]}')
    db.add(sg)
    db.commit()
    p = authed_client.post("/content-profiles", json=_profile_body()).json()
    authed_client.post(
        f"/content-profiles/{p['id']}/hosts",
        json={"host_id": host_with_group.id},
    )
    authed_client.post(
        f"/content-profiles/{p['id']}/groups",
        json={"group_id": host_with_group.group_id},
    )
    authed_client.post(
        f"/content-profiles/{p['id']}/smart-groups",
        json={"smart_group_id": sg.id},
    )
    res = authed_client.get(f"/content-profiles/{p['id']}/subscriptions")
    assert res.status_code == 200
    kinds = sorted(s["scope_kind"] for s in res.json())
    assert kinds == ["group", "host", "smart_group"]


# ---------------------------------------------------------------------------
# Effective-profile resolution endpoint
# ---------------------------------------------------------------------------


def test_effective_profile_no_profile_for_unbound_host(authed_client, host_with_group):
    res = authed_client.get(f"/systems/{host_with_group.id}/content-profile")
    assert res.status_code == 200
    body = res.json()
    assert body["state"] == "no_profile"
    assert body["profile"] is None
    assert body["conflict_bindings"] == []


def test_effective_profile_resolved_via_direct_binding(authed_client, host_with_group):
    p = authed_client.post("/content-profiles", json=_profile_body()).json()
    authed_client.post(
        f"/content-profiles/{p['id']}/hosts",
        json={"host_id": host_with_group.id},
    )
    res = authed_client.get(f"/systems/{host_with_group.id}/content-profile")
    body = res.json()
    assert body["state"] == "resolved"
    assert body["profile"]["profile_id"] == p["id"]
    assert body["profile"]["via_kind"] == "direct"


def test_effective_profile_conflict_at_direct_tier(authed_client, host_with_group):
    p1 = authed_client.post(
        "/content-profiles", json=_profile_body(slug="prof-1")
    ).json()
    p2 = authed_client.post(
        "/content-profiles", json=_profile_body(slug="prof-2")
    ).json()
    for p in (p1, p2):
        authed_client.post(
            f"/content-profiles/{p['id']}/hosts",
            json={"host_id": host_with_group.id},
        )
    body = authed_client.get(f"/systems/{host_with_group.id}/content-profile").json()
    assert body["state"] == "conflict"
    assert body["profile"] is None
    assert {b["profile_slug"] for b in body["conflict_bindings"]} == {
        "prof-1",
        "prof-2",
    }


def test_effective_profile_direct_wins_over_group(authed_client, host_with_group):
    direct = authed_client.post(
        "/content-profiles", json=_profile_body(slug="direct-p")
    ).json()
    via_group = authed_client.post(
        "/content-profiles", json=_profile_body(slug="group-p")
    ).json()

    # Direct binding to host
    authed_client.post(
        f"/content-profiles/{direct['id']}/hosts",
        json={"host_id": host_with_group.id},
    )
    # Group binding for host's group
    authed_client.post(
        f"/content-profiles/{via_group['id']}/groups",
        json={"group_id": host_with_group.group_id},
    )

    body = authed_client.get(f"/systems/{host_with_group.id}/content-profile").json()
    assert body["state"] == "resolved"
    assert body["profile"]["profile_slug"] == "direct-p"
    assert body["profile"]["via_kind"] == "direct"


def test_effective_profile_unknown_system_404(authed_client):
    assert authed_client.get("/systems/999999/content-profile").status_code == 404
