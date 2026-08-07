"""PRA-159 #2: ContentProfileService.resolve_mirror_entries* +
content_profile_diff unit tests.

Covers:
  * resolve_mirror_entries_for_profile flattens (channel, mirror,
    suite, components, architectures, pin) correctly
  * suite_override beats mirror.distribution; null override inherits
  * pinned_run_id surfaces manifest_sha256 from referenced run
  * soft-deleted channel filtered out
  * resolve_content_for_host: no_profile / resolved / conflict
    states + entries population
  * compute_profile_diff: added / removed / changed at (package, arch)
  * compute_profile_manifest: package union view
  * missing manifest file is logged-and-skipped, not fatal
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

import pytest

from app.db.models import (
    ContentChannel,
    ContentChannelRepo,
    ContentProfile,
    ContentProfileChannel,
    Credential,
    Group,
    HostContentProfileSubscription,
    MirrorRepo,
    MirrorSyncRun,
    System,
)
from app.services.content_profile_diff import (
    compute_profile_diff,
    compute_profile_manifest,
)
from app.services.content_profile_service import ContentProfileService

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mirror_root(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    return tmp_path


def _make_mirror(
    db, slug: str, family: str = "deb", suite: str = "jammy"
) -> MirrorRepo:
    m = MirrorRepo(
        slug=slug,
        display_name=slug,
        package_family=family,
        upstream_url="http://x/y",
        distribution=suite,
        components='["main","universe"]' if family == "deb" else "[]",
        architectures='["amd64"]' if family == "deb" else '["x86_64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(m)
    db.flush()
    return m


def _make_channel(db, slug: str, family: str = "deb") -> ContentChannel:
    c = ContentChannel(slug=slug, display_name=slug, package_family=family)
    db.add(c)
    db.flush()
    return c


def _make_profile(db, slug: str, family: str = "deb") -> ContentProfile:
    p = ContentProfile(slug=slug, display_name=slug, package_family=family)
    db.add(p)
    db.flush()
    return p


def _link_channel_to_profile(db, profile, channel):
    db.add(ContentProfileChannel(profile_id=profile.id, channel_id=channel.id))
    db.flush()


def _add_repo(db, channel, mirror, *, suite_override=None, pinned_run_id=None):
    db.add(
        ContentChannelRepo(
            channel_id=channel.id,
            mirror_id=mirror.id,
            suite_override=suite_override,
            pinned_run_id=pinned_run_id,
        )
    )
    db.flush()


def _make_run(
    db,
    mirror,
    *,
    sha256="a" * 64,
    manifest_path=None,
    package_count=1,
    started_at=None,
):
    run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=started_at or datetime.utcnow(),
        finished_at=datetime.utcnow(),
        status="ok",
        run_kind="sync",
        manifest_sha256=sha256,
        manifest_path=manifest_path or f"/tmp/{mirror.slug}-run.manifest.json",
        byte_count=1234,
        package_count=package_count,
    )
    db.add(run)
    db.flush()
    return run


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="resolver-grp")
    db.add(g)
    db.flush()
    cred = Credential(name="resolver-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    s = System(
        hostname="resolver.example.com",
        ip_address="10.50.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.commit()
    return s


# ---------------------------------------------------------------------------
# resolve_mirror_entries_for_profile
# ---------------------------------------------------------------------------


def test_resolve_entries_inherits_suite_when_override_null(db):
    mirror = _make_mirror(db, "rm-1", suite="jammy")
    channel = _make_channel(db, "rc-1")
    profile = _make_profile(db, "rp-1")
    _link_channel_to_profile(db, profile, channel)
    _add_repo(db, channel, mirror)
    db.commit()

    entries = ContentProfileService(db).resolve_mirror_entries_for_profile(profile.id)
    assert len(entries) == 1
    e = entries[0]
    assert e.suite == "jammy"
    assert e.mirror_slug == "rm-1"
    assert e.channel_slug == "rc-1"
    assert e.package_family == "deb"
    assert e.components == ["main", "universe"]
    assert e.architectures == ["amd64"]
    assert e.pinned_run_id is None
    assert e.pinned_manifest_sha256 is None


def test_resolve_entries_suite_override_wins(db):
    mirror = _make_mirror(db, "rm-2", suite="jammy")
    channel = _make_channel(db, "rc-2")
    profile = _make_profile(db, "rp-2")
    _link_channel_to_profile(db, profile, channel)
    _add_repo(db, channel, mirror, suite_override="jammy-security")
    _add_repo(db, channel, mirror, suite_override="jammy-updates")
    db.commit()

    suites = sorted(
        e.suite
        for e in ContentProfileService(db).resolve_mirror_entries_for_profile(
            profile.id
        )
    )
    assert suites == ["jammy-security", "jammy-updates"]


def test_resolve_entries_pinned_surfaces_manifest_sha(db):
    mirror = _make_mirror(db, "rm-3")
    run = _make_run(db, mirror, sha256="b" * 64)
    channel = _make_channel(db, "rc-3")
    profile = _make_profile(db, "rp-3")
    _link_channel_to_profile(db, profile, channel)
    _add_repo(db, channel, mirror, pinned_run_id=run.id)
    db.commit()

    entries = ContentProfileService(db).resolve_mirror_entries_for_profile(profile.id)
    assert entries[0].pinned_run_id == run.id
    assert entries[0].pinned_manifest_sha256 == "b" * 64


def test_resolve_entries_skips_soft_deleted_channel(db):
    mirror = _make_mirror(db, "rm-4")
    channel = _make_channel(db, "rc-4")
    profile = _make_profile(db, "rp-4")
    _link_channel_to_profile(db, profile, channel)
    _add_repo(db, channel, mirror)
    channel.deleted_at = datetime.utcnow()
    db.commit()

    entries = ContentProfileService(db).resolve_mirror_entries_for_profile(profile.id)
    assert entries == []


def test_resolve_entries_skips_soft_deleted_mirror(db):
    mirror = _make_mirror(db, "rm-5")
    channel = _make_channel(db, "rc-5")
    profile = _make_profile(db, "rp-5")
    _link_channel_to_profile(db, profile, channel)
    _add_repo(db, channel, mirror)
    mirror.deleted_at = datetime.utcnow()
    db.commit()

    entries = ContentProfileService(db).resolve_mirror_entries_for_profile(profile.id)
    assert entries == []


# ---------------------------------------------------------------------------
# resolve_content_for_host
# ---------------------------------------------------------------------------


def test_resolve_content_no_profile(db, host):
    result = ContentProfileService(db).resolve_content_for_host(host.id)
    assert result.state == "no_profile"
    assert result.entries == []


def test_resolve_content_resolved_returns_entries(db, host):
    mirror = _make_mirror(db, "rm-host-1")
    channel = _make_channel(db, "rc-host-1")
    profile = _make_profile(db, "rp-host-1")
    _link_channel_to_profile(db, profile, channel)
    _add_repo(db, channel, mirror)
    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=profile.id))
    db.commit()

    result = ContentProfileService(db).resolve_content_for_host(host.id)
    assert result.state == "resolved"
    assert len(result.entries) == 1
    assert result.entries[0].mirror_slug == "rm-host-1"


def test_resolve_content_conflict_returns_no_entries(db, host):
    p1 = _make_profile(db, "conflict-1")
    p2 = _make_profile(db, "conflict-2")
    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=p1.id))
    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=p2.id))
    db.commit()

    result = ContentProfileService(db).resolve_content_for_host(host.id)
    assert result.state == "conflict"
    assert result.entries == []
    assert {b.profile_id for b in result.conflict_bindings} == {p1.id, p2.id}


# ---------------------------------------------------------------------------
# compute_profile_manifest + compute_profile_diff
# ---------------------------------------------------------------------------


def _write_manifest(path: Path, files: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "praxis_mirror_manifest": "v1",
        "mirror_slug": "x",
        "run_id": 1,
        "package_family": "deb",
        "byte_count": 0,
        "package_count": len([f for f in files if f.get("package")]),
        "files": files,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_profile_manifest_packages_aggregated(db, tmp_path):
    mirror = _make_mirror(db, "diff-mirror-1")
    manifest_path = tmp_path / "diff-1.manifest.json"
    _write_manifest(
        manifest_path,
        [
            {
                "filename": "a.deb",
                "sha256": "x",
                "size": 1,
                "package": "curl",
                "version": "8.0",
                "arch": "amd64",
            },
            {
                "filename": "b.deb",
                "sha256": "y",
                "size": 1,
                "package": "vim",
                "version": "9.0",
                "arch": "amd64",
            },
            {
                "filename": "Release",
                "sha256": "z",
                "size": 1,
                "package": None,
                "version": None,
                "arch": None,
            },
        ],
    )
    run = _make_run(db, mirror, manifest_path=str(manifest_path))
    channel = _make_channel(db, "diff-c-1")
    profile = _make_profile(db, "diff-p-1")
    _link_channel_to_profile(db, profile, channel)
    _add_repo(db, channel, mirror, pinned_run_id=run.id)
    db.commit()

    out = compute_profile_manifest(db, profile.id)
    names = sorted(p["package"] for p in out["packages"])
    assert names == ["curl", "vim"]
    assert out["summary"]["package_count"] == 2


def test_profile_diff_added_removed_changed(db, tmp_path):
    mirror_a = _make_mirror(db, "diff-mirror-A")
    mirror_b = _make_mirror(db, "diff-mirror-B")
    manifest_a = tmp_path / "A.manifest.json"
    manifest_b = tmp_path / "B.manifest.json"
    _write_manifest(
        manifest_a,
        [
            # in both, same version
            {
                "filename": "curl.deb",
                "sha256": "x",
                "size": 1,
                "package": "curl",
                "version": "8.0",
                "arch": "amd64",
            },
            # in A only — should appear in `removed`
            {
                "filename": "vim.deb",
                "sha256": "x",
                "size": 1,
                "package": "vim",
                "version": "9.0",
                "arch": "amd64",
            },
            # in both with different version — `changed`
            {
                "filename": "openssl.deb",
                "sha256": "x",
                "size": 1,
                "package": "openssl",
                "version": "3.0",
                "arch": "amd64",
            },
        ],
    )
    _write_manifest(
        manifest_b,
        [
            {
                "filename": "curl.deb",
                "sha256": "x",
                "size": 1,
                "package": "curl",
                "version": "8.0",
                "arch": "amd64",
            },
            # in B only — should appear in `added`
            {
                "filename": "nginx.deb",
                "sha256": "x",
                "size": 1,
                "package": "nginx",
                "version": "1.25",
                "arch": "amd64",
            },
            {
                "filename": "openssl.deb",
                "sha256": "x",
                "size": 1,
                "package": "openssl",
                "version": "3.1",
                "arch": "amd64",
            },
        ],
    )
    run_a = _make_run(db, mirror_a, manifest_path=str(manifest_a))
    run_b = _make_run(db, mirror_b, manifest_path=str(manifest_b))

    channel_a = _make_channel(db, "diff-c-A")
    channel_b = _make_channel(db, "diff-c-B")
    profile_a = _make_profile(db, "diff-p-A")
    profile_b = _make_profile(db, "diff-p-B")
    _link_channel_to_profile(db, profile_a, channel_a)
    _link_channel_to_profile(db, profile_b, channel_b)
    _add_repo(db, channel_a, mirror_a, pinned_run_id=run_a.id)
    _add_repo(db, channel_b, mirror_b, pinned_run_id=run_b.id)
    db.commit()

    diff = compute_profile_diff(
        db, from_profile_id=profile_a.id, to_profile_id=profile_b.id
    )
    added = {(r["package"], r["arch"]) for r in diff["added"]}
    removed = {(r["package"], r["arch"]) for r in diff["removed"]}
    changed = {(r["package"], r["arch"]) for r in diff["changed"]}
    assert added == {("nginx", "amd64")}
    assert removed == {("vim", "amd64")}
    assert changed == {("openssl", "amd64")}

    openssl = next(r for r in diff["changed"] if r["package"] == "openssl")
    assert openssl["from_version"] == "3.0"
    assert openssl["to_version"] == "3.1"

    assert diff["summary"]["added_count"] == 1
    assert diff["summary"]["removed_count"] == 1
    assert diff["summary"]["changed_count"] == 1


def test_profile_diff_missing_manifest_treated_as_empty(db, tmp_path):
    mirror_a = _make_mirror(db, "diff-missing-A")
    mirror_b = _make_mirror(db, "diff-missing-B")
    # B has a real manifest, A's manifest path doesn't exist on disk.
    manifest_b = tmp_path / "B.manifest.json"
    _write_manifest(
        manifest_b,
        [
            {
                "filename": "x.deb",
                "sha256": "x",
                "size": 1,
                "package": "x",
                "version": "1.0",
                "arch": "amd64",
            },
        ],
    )
    run_a = _make_run(db, mirror_a, manifest_path=str(tmp_path / "does-not-exist.json"))
    run_b = _make_run(db, mirror_b, manifest_path=str(manifest_b))

    chan_a = _make_channel(db, "missing-c-A")
    chan_b = _make_channel(db, "missing-c-B")
    p_a = _make_profile(db, "missing-p-A")
    p_b = _make_profile(db, "missing-p-B")
    _link_channel_to_profile(db, p_a, chan_a)
    _link_channel_to_profile(db, p_b, chan_b)
    _add_repo(db, chan_a, mirror_a, pinned_run_id=run_a.id)
    _add_repo(db, chan_b, mirror_b, pinned_run_id=run_b.id)
    db.commit()

    diff = compute_profile_diff(db, from_profile_id=p_a.id, to_profile_id=p_b.id)
    # A contributes 0 packages → all of B's packages appear as added.
    assert diff["summary"]["added_count"] == 1
    assert diff["summary"]["from_package_count"] == 0


def test_profile_diff_unpinned_uses_latest_ok_run(db, tmp_path):
    """When a repo is unpinned, the diff helper picks the most
    recent ok run for the mirror."""
    mirror = _make_mirror(db, "diff-unpinned-mirror")
    older_path = tmp_path / "older.manifest.json"
    newer_path = tmp_path / "newer.manifest.json"
    _write_manifest(
        older_path,
        [
            {
                "filename": "a.deb",
                "sha256": "x",
                "size": 1,
                "package": "a",
                "version": "1.0",
                "arch": "amd64",
            },
        ],
    )
    _write_manifest(
        newer_path,
        [
            {
                "filename": "a.deb",
                "sha256": "x",
                "size": 1,
                "package": "a",
                "version": "2.0",
                "arch": "amd64",
            },
        ],
    )
    older = _make_run(
        db,
        mirror,
        manifest_path=str(older_path),
        started_at=datetime(2026, 1, 1),
    )
    newer = _make_run(
        db,
        mirror,
        manifest_path=str(newer_path),
        started_at=datetime(2026, 5, 1),
    )

    channel = _make_channel(db, "unpinned-c")
    profile = _make_profile(db, "unpinned-p")
    _link_channel_to_profile(db, profile, channel)
    _add_repo(db, channel, mirror)  # unpinned
    db.commit()

    out = compute_profile_manifest(db, profile.id)
    versions = {p["package"]: p["version"] for p in out["packages"]}
    assert versions == {"a": "2.0"}
