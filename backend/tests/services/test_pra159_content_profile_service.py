"""PRA-159 #1: ContentProfileService unit tests.

Covers:
  * resolve_effective three-state result + tier precedence
  * conflict at each tier
  * soft-deleted profile filtered out of resolution
  * disabled smart group ignored
  * cross-table validation helpers (family match, pin validation)
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.db.models import (
    ContentProfile,
    Credential,
    Group,
    GroupContentProfileSubscription,
    HostContentProfileSubscription,
    MirrorRepo,
    MirrorSyncRun,
    SmartGroup,
    SmartGroupContentProfileSubscription,
    SmartGroupMembership,
    System,
)
from app.services.content_profile_service import (
    ContentProfileError,
    ContentProfileService,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def host_factory(db, seed_distro):
    counter = {"n": 0}

    def make(group: Group | None = None) -> System:
        counter["n"] += 1
        n = counter["n"]
        if group is None:
            group = Group(name=f"sg-{n}")
            db.add(group)
            db.flush()
        cred = Credential(name=f"cred-svc-{n}", auth_method="ssh_key", username="root")
        db.add(cred)
        db.flush()
        s = System(
            hostname=f"svc-host-{n}.example.com",
            ip_address=f"10.0.0.{n}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=group.id,
            credentials_id=cred.id,
        )
        db.add(s)
        db.flush()
        db.commit()
        return s

    return make


@pytest.fixture
def profile_factory(db):
    counter = {"n": 0}

    def make(slug: str | None = None, package_family: str = "deb") -> ContentProfile:
        counter["n"] += 1
        slug = slug or f"prof-{counter['n']}"
        p = ContentProfile(
            slug=slug,
            display_name=slug,
            package_family=package_family,
        )
        db.add(p)
        db.flush()
        db.commit()
        return p

    return make


@pytest.fixture
def smart_group_factory(db):
    counter = {"n": 0}

    def make(name: str | None = None, enabled: bool = True) -> SmartGroup:
        counter["n"] += 1
        sg = SmartGroup(
            name=name or f"sg-svc-{counter['n']}",
            rule_json='{"op":"and","rules":[]}',
            enabled=enabled,
        )
        db.add(sg)
        db.flush()
        db.commit()
        return sg

    return make


def _bind_host(db, host, profile):
    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=profile.id))
    db.commit()


def _bind_group(db, group, profile):
    db.add(GroupContentProfileSubscription(group_id=group.id, profile_id=profile.id))
    db.commit()


def _bind_smart_group(db, sg, profile):
    db.add(
        SmartGroupContentProfileSubscription(
            smart_group_id=sg.id, profile_id=profile.id
        )
    )
    db.commit()


def _add_smart_membership(db, sg, host):
    db.add(SmartGroupMembership(smart_group_id=sg.id, system_id=host.id))
    db.commit()


# ---------------------------------------------------------------------------
# resolve_effective — three-state behaviour
# ---------------------------------------------------------------------------


def test_resolve_no_profile_for_unbound_host(db, host_factory):
    host = host_factory()
    result = ContentProfileService(db).resolve_effective(host.id)
    assert result.state == "no_profile"
    assert result.profile is None
    assert result.conflict_bindings == []


def test_resolve_resolved_via_direct(db, host_factory, profile_factory):
    host = host_factory()
    p = profile_factory("only-prof")
    _bind_host(db, host, p)

    result = ContentProfileService(db).resolve_effective(host.id)
    assert result.state == "resolved"
    assert result.profile.profile_id == p.id
    assert result.profile.via_kind == "direct"
    assert result.profile.via_id is None


def test_resolve_conflict_at_direct(db, host_factory, profile_factory):
    host = host_factory()
    p1 = profile_factory("d1")
    p2 = profile_factory("d2")
    _bind_host(db, host, p1)
    _bind_host(db, host, p2)

    result = ContentProfileService(db).resolve_effective(host.id)
    assert result.state == "conflict"
    assert result.profile is None
    assert {b.profile_id for b in result.conflict_bindings} == {p1.id, p2.id}


def test_direct_wins_over_group_even_when_group_has_conflict(
    db, host_factory, profile_factory
):
    """If the host has a single direct subscription, group-tier
    conflicts are NOT surfaced — precedence is strict."""
    host = host_factory()
    direct_p = profile_factory("direct")
    g_p1 = profile_factory("g1")
    g_p2 = profile_factory("g2")

    _bind_host(db, host, direct_p)
    _bind_group(db, host.group, g_p1)
    _bind_group(db, host.group, g_p2)

    result = ContentProfileService(db).resolve_effective(host.id)
    assert result.state == "resolved"
    assert result.profile.profile_id == direct_p.id


def test_resolve_via_group(db, host_factory, profile_factory):
    host = host_factory()
    p = profile_factory("via-group")
    _bind_group(db, host.group, p)

    result = ContentProfileService(db).resolve_effective(host.id)
    assert result.state == "resolved"
    assert result.profile.profile_id == p.id
    assert result.profile.via_kind == "group"
    assert result.profile.via_id == host.group_id
    assert result.profile.via_label == host.group.name


def test_conflict_at_group_tier(db, host_factory, profile_factory):
    host = host_factory()
    p1 = profile_factory("g-conflict-1")
    p2 = profile_factory("g-conflict-2")
    _bind_group(db, host.group, p1)
    _bind_group(db, host.group, p2)

    result = ContentProfileService(db).resolve_effective(host.id)
    assert result.state == "conflict"
    assert {b.profile_id for b in result.conflict_bindings} == {p1.id, p2.id}
    assert all(b.via_kind == "group" for b in result.conflict_bindings)


def test_group_wins_over_smart_group(
    db, host_factory, profile_factory, smart_group_factory
):
    host = host_factory()
    g_p = profile_factory("group-tier")
    sg_p = profile_factory("smart-tier")
    sg = smart_group_factory()
    _add_smart_membership(db, sg, host)
    _bind_smart_group(db, sg, sg_p)
    _bind_group(db, host.group, g_p)

    result = ContentProfileService(db).resolve_effective(host.id)
    assert result.state == "resolved"
    assert result.profile.profile_slug == "group-tier"


def test_resolve_via_smart_group(
    db, host_factory, profile_factory, smart_group_factory
):
    host = host_factory()
    sg = smart_group_factory()
    _add_smart_membership(db, sg, host)
    p = profile_factory("via-smart")
    _bind_smart_group(db, sg, p)

    result = ContentProfileService(db).resolve_effective(host.id)
    assert result.state == "resolved"
    assert result.profile.profile_id == p.id
    assert result.profile.via_kind == "smart_group"
    assert result.profile.via_id == sg.id


def test_disabled_smart_group_ignored(
    db, host_factory, profile_factory, smart_group_factory
):
    host = host_factory()
    sg = smart_group_factory(enabled=False)
    _add_smart_membership(db, sg, host)
    p = profile_factory("would-be-via-smart")
    _bind_smart_group(db, sg, p)

    result = ContentProfileService(db).resolve_effective(host.id)
    assert result.state == "no_profile"


def test_conflict_at_smart_group_tier(
    db, host_factory, profile_factory, smart_group_factory
):
    host = host_factory()
    sg1 = smart_group_factory()
    sg2 = smart_group_factory()
    _add_smart_membership(db, sg1, host)
    _add_smart_membership(db, sg2, host)
    p1 = profile_factory("sg1-p")
    p2 = profile_factory("sg2-p")
    _bind_smart_group(db, sg1, p1)
    _bind_smart_group(db, sg2, p2)

    result = ContentProfileService(db).resolve_effective(host.id)
    assert result.state == "conflict"
    assert {b.profile_id for b in result.conflict_bindings} == {p1.id, p2.id}


def test_two_subscriptions_pointing_at_same_profile_is_resolved(
    db, host_factory, profile_factory, smart_group_factory
):
    """Two bindings of the SAME profile from different sources is
    NOT a conflict — distinct profile count is what matters."""
    host = host_factory()
    sg1 = smart_group_factory()
    sg2 = smart_group_factory()
    _add_smart_membership(db, sg1, host)
    _add_smart_membership(db, sg2, host)
    p = profile_factory("shared")
    _bind_smart_group(db, sg1, p)
    _bind_smart_group(db, sg2, p)

    result = ContentProfileService(db).resolve_effective(host.id)
    assert result.state == "resolved"
    assert result.profile.profile_id == p.id


def test_soft_deleted_profile_filtered_at_every_tier(
    db, host_factory, profile_factory, smart_group_factory
):
    host = host_factory()
    p = profile_factory("dead-prof")
    _bind_host(db, host, p)
    p.deleted_at = datetime.utcnow()
    db.commit()

    result = ContentProfileService(db).resolve_effective(host.id)
    assert result.state == "no_profile"


# ---------------------------------------------------------------------------
# Cross-table validation helpers
# ---------------------------------------------------------------------------


def test_assert_channel_repo_family_match_ok():
    ContentProfileService.assert_channel_repo_family_match("deb", "deb")


def test_assert_channel_repo_family_match_mismatch():
    with pytest.raises(ContentProfileError, match="package_family"):
        ContentProfileService.assert_channel_repo_family_match("deb", "rpm")


def test_assert_profile_channel_family_match(db, profile_factory):
    p = profile_factory(package_family="rpm")
    svc = ContentProfileService(db)
    svc.assert_profile_channel_family_match(p, "rpm")
    with pytest.raises(ContentProfileError):
        svc.assert_profile_channel_family_match(p, "deb")


def test_assert_pinned_run_belongs_to_mirror_ok(db):
    mirror = MirrorRepo(
        slug="svc-mirror",
        display_name="m",
        package_family="deb",
        upstream_url="http://x/y",
        distribution="jammy",
        components="[]",
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(mirror)
    db.flush()
    run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        status="ok",
        run_kind="sync",
        manifest_sha256="b" * 64,
        manifest_path="/x",
        byte_count=1,
        package_count=1,
    )
    db.add(run)
    db.commit()
    sha, path = ContentProfileService(db).assert_pinned_run_belongs_to_mirror(
        run.id, mirror.id
    )
    assert sha == "b" * 64
    assert path == "/x"


def test_assert_pinned_run_rejects_wrong_mirror(db):
    m1 = MirrorRepo(
        slug="svc-m1",
        display_name="m1",
        package_family="deb",
        upstream_url="http://x/y",
        distribution="jammy",
        components="[]",
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    m2 = MirrorRepo(
        slug="svc-m2",
        display_name="m2",
        package_family="deb",
        upstream_url="http://x/z",
        distribution="jammy",
        components="[]",
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add_all([m1, m2])
    db.flush()
    run = MirrorSyncRun(
        mirror_repo_id=m1.id,
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        status="ok",
        run_kind="sync",
        manifest_sha256="c" * 64,
        manifest_path="/x",
        byte_count=1,
        package_count=1,
    )
    db.add(run)
    db.commit()
    with pytest.raises(ContentProfileError, match="belongs to mirror"):
        ContentProfileService(db).assert_pinned_run_belongs_to_mirror(run.id, m2.id)


def test_assert_pinned_run_rejects_failed_status(db):
    mirror = MirrorRepo(
        slug="svc-failed",
        display_name="m",
        package_family="deb",
        upstream_url="http://x/y",
        distribution="jammy",
        components="[]",
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(mirror)
    db.flush()
    run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        status="failed",
        run_kind="sync",
        error_text="boom",
    )
    db.add(run)
    db.commit()
    with pytest.raises(ContentProfileError, match="status"):
        ContentProfileService(db).assert_pinned_run_belongs_to_mirror(run.id, mirror.id)


def test_assert_pinned_run_unknown_id(db):
    with pytest.raises(ContentProfileError, match="not found"):
        ContentProfileService(db).assert_pinned_run_belongs_to_mirror(999999, 1)
