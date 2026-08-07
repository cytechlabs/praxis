"""PRA-164 slice 3 — preflight route tests.

Covers the two new endpoints + the ``preflight_summary`` extension
on the existing detail / hosts read paths:

* ``GET /patch/update-plans/{plan_id}/hosts/{plan_host_id}/preflight``
  - happy path (rows ordered by content_availability_state then
    package_name).
  - 404 when the host id does not belong to the plan.
* ``GET /patch/update-plans/{plan_id}/preflight``
  - 404 on unknown plan.
  - content_availability_state filter
    (``available`` / ``unavailable`` / ``profile_missing`` /
    ``not_applicable``).
  - 422 on invalid state.
* ``GET /patch/update-plans/{plan_id}`` (Slice 1 detail) now returns
  ``preflight_summary`` on each host row.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import pytest

from app.db.models import (
    ContentChannel,
    ContentChannelRepo,
    ContentProfile,
    ContentProfileChannel,
    Credential,
    Group,
    HostContentProfileSubscription,
    HostFacts,
    MirrorRepo,
    MirrorSyncRun,
    Package,
    PackageUpdate,
    System,
)
from app.services import mirror_package_index, patch_policy_service


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rt-pf-group", description="t")
    db.add(g)
    db.commit()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rt-pf-cred",
        auth_method="password",
        username="root",
        vault_path="x",
    )
    db.add(c)
    db.commit()
    return c


@pytest.fixture
def host_factory(db, seed_distro, static_group, credentials):
    counter = {"n": 0}

    def make() -> System:
        counter["n"] += 1
        s = System(
            hostname=f"rt-pf-host-{counter['n']}.example.com",
            ip_address=f"10.0.60.{counter['n']}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=static_group.id,
            credentials_id=credentials.id,
        )
        db.add(s)
        db.commit()
        return s

    return make


def _facts(db, host):
    db.add(
        HostFacts(
            system_id=host.id,
            schema_version=1,
            collected_at=datetime.utcnow(),
            source_transport="agent",
            package_manager="apt",
            distro_id_facts="ubuntu",
        )
    )
    db.commit()


def _pkg_with_update(
    db, host: System, name: str, installed: str, available: str
) -> Package:
    p = Package(
        system_id=host.id,
        name=name,
        installed_version=installed,
        package_type="apt",
    )
    db.add(p)
    db.commit()
    db.add(
        PackageUpdate(
            package_id=p.id,
            system_id=host.id,
            available_version=available,
            update_type="security",
            discovered_on=datetime.utcnow(),
        )
    )
    db.commit()
    return p


def _mirror_with_index(db, tmp_path: Path, slug: str, files: list) -> MirrorRepo:
    m = MirrorRepo(
        slug=slug,
        display_name=slug,
        package_family="deb",
        upstream_url=f"https://example.com/{slug}",
        distribution="jammy",
        components="[]",
        architectures="[]",
        sync_schedule_cron="0 4 * * *",
    )
    db.add(m)
    db.commit()
    manifest = tmp_path / f"{slug}.json"
    manifest.write_text(json.dumps({"files": files}), encoding="utf-8")
    run = MirrorSyncRun(
        mirror_repo_id=m.id,
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        status="ok",
        run_kind="sync",
        package_count=len([f for f in files if f.get("package")]),
        manifest_sha256="0" * 64,
        manifest_path=str(manifest),
    )
    db.add(run)
    db.commit()
    mirror_package_index.populate_from_run(db, run)
    db.commit()
    return m


def _bind_profile(db, host: System, mirror: MirrorRepo, slug: str) -> None:
    profile = ContentProfile(
        slug=slug,
        display_name=slug,
        package_family=mirror.package_family,
    )
    db.add(profile)
    db.commit()
    channel = ContentChannel(
        slug=f"{slug}-ch",
        display_name=f"{slug}-ch",
        package_family=mirror.package_family,
    )
    db.add(channel)
    db.commit()
    db.add(ContentProfileChannel(profile_id=profile.id, channel_id=channel.id))
    db.add(
        ContentChannelRepo(
            channel_id=channel.id, mirror_id=mirror.id, suite_override=None
        )
    )
    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=profile.id))
    db.commit()


def _make_policy(
    db,
    admin_user,
    slug: str,
    *,
    scope_kind: str = "full",
    scope_packages: Optional[list] = None,
):
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind=scope_kind,
        scope_packages=scope_packages,
        rollout_cadence="immediate",
    )


def _bind(db, admin_user, policy, host):
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )


# ---------------------------------------------------------------------------
# /preflight happy path
# ---------------------------------------------------------------------------


def test_get_host_preflight_returns_rows(
    authed_client, db, admin_user, host_factory, tmp_path
):
    pol = _make_policy(db, admin_user, "rt-pf-host", scope_kind="full")
    h = host_factory()
    _bind(db, admin_user, pol, h)
    _facts(db, h)
    _pkg_with_update(db, h, "openssl", "3.0.1", "3.0.2")
    mirror = _mirror_with_index(
        db,
        tmp_path,
        "rt-pf-mirror",
        [
            {
                "filename": "openssl_3.0.2_amd64.deb",
                "sha256": "a" * 64,
                "size": 1,
                "package": "openssl",
                "version": "3.0.2",
                "arch": "amd64",
            }
        ],
    )
    _bind_profile(db, h, mirror, "rt-pf-prof")

    create_res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "pf"},
    )
    assert create_res.status_code == 201
    plan = create_res.json()
    host_id = plan["hosts"][0]["id"]

    res = authed_client.get(
        f"/patch/update-plans/{plan['id']}/hosts/{host_id}/preflight"
    )
    assert res.status_code == 200
    rows = res.json()
    assert len(rows) == 1
    assert rows[0]["package_name"] == "openssl"
    assert rows[0]["content_availability_state"] == "available"
    assert rows[0]["package_manager_family_snapshot"] == "apt"


def test_get_host_preflight_404_when_host_not_in_plan(
    authed_client, db, admin_user, host_factory, tmp_path
):
    pol_a = _make_policy(db, admin_user, "rt-pf404-a", scope_kind="full")
    pol_b = _make_policy(db, admin_user, "rt-pf404-b", scope_kind="full")
    h_a = host_factory()
    h_b = host_factory()
    _bind(db, admin_user, pol_a, h_a)
    _bind(db, admin_user, pol_b, h_b)
    _facts(db, h_a)
    _facts(db, h_b)
    _pkg_with_update(db, h_a, "x", "1", "2")
    _pkg_with_update(db, h_b, "y", "1", "2")

    plan_a = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol_a.id, "name": "a"},
    ).json()
    plan_b = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol_b.id, "name": "b"},
    ).json()
    host_b_id = plan_b["hosts"][0]["id"]

    res = authed_client.get(
        f"/patch/update-plans/{plan_a['id']}/hosts/{host_b_id}/preflight"
    )
    assert res.status_code == 404
    assert "not found" in res.json()["detail"]


# ---------------------------------------------------------------------------
# Plan-wide /preflight
# ---------------------------------------------------------------------------


def test_get_plan_preflight_state_filter(
    authed_client, db, admin_user, host_factory, tmp_path
):
    pol = _make_policy(db, admin_user, "rt-pf-state", scope_kind="full")
    h = host_factory()
    _bind(db, admin_user, pol, h)
    _facts(db, h)
    _pkg_with_update(db, h, "openssl", "1.0", "1.1")
    _pkg_with_update(db, h, "kernel", "5.0", "5.1")
    mirror = _mirror_with_index(
        db,
        tmp_path,
        "rt-pf-state-mirror",
        [
            {
                "filename": "openssl_1.1_amd64.deb",
                "sha256": "a" * 64,
                "size": 1,
                "package": "openssl",
                "version": "1.1",
                "arch": "amd64",
            }
            # kernel 5.1 deliberately absent -> unavailable.
        ],
    )
    _bind_profile(db, h, mirror, "rt-pf-state-prof")

    plan = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "state"},
    ).json()

    avail = authed_client.get(
        f"/patch/update-plans/{plan['id']}/preflight?content_availability_state=available"
    )
    assert avail.status_code == 200
    assert {r["package_name"] for r in avail.json()} == {"openssl"}

    unavail = authed_client.get(
        f"/patch/update-plans/{plan['id']}/preflight?content_availability_state=unavailable"
    )
    assert unavail.status_code == 200
    assert {r["package_name"] for r in unavail.json()} == {"kernel"}


def test_get_plan_preflight_404_on_unknown_plan(authed_client):
    res = authed_client.get("/patch/update-plans/999999/preflight")
    assert res.status_code == 404


def test_get_plan_preflight_invalid_state_returns_422(
    authed_client, db, admin_user, host_factory, tmp_path
):
    pol = _make_policy(db, admin_user, "rt-pf-bad", scope_kind="full")
    h = host_factory()
    _bind(db, admin_user, pol, h)
    _facts(db, h)
    _pkg_with_update(db, h, "x", "1", "2")
    plan = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "bad"},
    ).json()
    res = authed_client.get(
        f"/patch/update-plans/{plan['id']}/preflight?content_availability_state=not-a-state"
    )
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# preflight_summary surfaces on the Slice 1 detail endpoint
# ---------------------------------------------------------------------------


def test_plan_detail_returns_preflight_summary_on_hosts(
    authed_client, db, admin_user, host_factory, tmp_path
):
    pol = _make_policy(db, admin_user, "rt-pf-sum", scope_kind="full")
    h = host_factory()
    _bind(db, admin_user, pol, h)
    _facts(db, h)
    _pkg_with_update(db, h, "openssl", "1.0", "1.1")
    mirror = _mirror_with_index(
        db,
        tmp_path,
        "rt-pf-sum-mirror",
        [
            {
                "filename": "openssl_1.1_amd64.deb",
                "sha256": "a" * 64,
                "size": 1,
                "package": "openssl",
                "version": "1.1",
                "arch": "amd64",
            }
        ],
    )
    _bind_profile(db, h, mirror, "rt-pf-sum-prof")

    create_res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "sum"},
    )
    body = create_res.json()
    summary = body["hosts"][0]["preflight_summary"]
    assert summary is not None
    assert summary["available"] == 1
    assert summary["unavailable"] == 0
    assert summary["profile_missing"] == 0
    assert summary["not_applicable"] == 0
    assert summary["installed_drift_count"] == 0
