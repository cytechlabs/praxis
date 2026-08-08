"""PRA-160 slice #1: AirgapPlanner unit tests.

Covers:
  * Profile resolution: unknown / soft-deleted / mixed-family rejection.
  * Mirror selection: latest vs pinned base, per-mirror explicit
    override, override-not-in-scope rejection.
  * Critical byte-match validation: pinned/explicit run whose
    manifest_sha disagrees with current live → refusal.
  * Empty-resolved (profiles compose no live mirrors) refusal.
  * Descriptor structure (single family, deterministic ordering,
    payload_index empty for slice #1).
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.models import (
    ContentChannel,
    ContentChannelRepo,
    ContentProfile,
    ContentProfileChannel,
    MirrorRepo,
    MirrorSigningKey,
    MirrorSyncRun,
)
from app.services.airgap.planner import (
    AirgapPlanner,
    ConflictingPins,
    EmptyProfile,
    HistoricalBytesUnavailable,
    InvalidOverrideRun,
    MirrorSigningMaterialMissing,
    MixedPackageFamily,
    NoSnapshotAvailable,
    PinUnusable,
    UnknownOverrideMirror,
    UnknownProfile,
)
from app.services.airgap.schema import BUNDLE_SCHEMA_VERSION

_FPR = "AA00000000000000000000000000000000000001"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mirror_factory(db):
    counter = {"n": 0}

    def make(
        slug: str | None = None,
        package_family: str = "deb",
        distribution: str = "jammy",
        components: str = '["main"]',
        architectures: str = '["amd64"]',
    ) -> MirrorRepo:
        counter["n"] += 1
        slug = slug or f"mirror-{counter['n']}"
        m = MirrorRepo(
            slug=slug,
            display_name=slug,
            package_family=package_family,
            upstream_url=f"http://example.com/{slug}",
            distribution=distribution,
            components=components,
            architectures=architectures,
            sync_schedule_cron="0 2 * * *",
            last_sync_status="ok",
            current_disk_bytes=0,
        )
        db.add(m)
        db.commit()
        db.refresh(m)
        return m

    return make


@pytest.fixture
def run_factory(db):
    """Create a status='ok' mirror_sync_runs row.

    ``offset_seconds`` controls ``started_at`` so multiple runs for
    one mirror have a deterministic ordering. ``manifest_sha`` is the
    operator-supplied content-fingerprint so the byte-match validator
    has something to compare.
    """

    counter = {"n": 0}

    def make(
        mirror: MirrorRepo,
        manifest_sha: str,
        offset_seconds: int = 0,
        status: str = "ok",
    ) -> MirrorSyncRun:
        counter["n"] += 1
        run = MirrorSyncRun(
            mirror_repo_id=mirror.id,
            started_at=datetime.utcnow() + timedelta(seconds=offset_seconds),
            finished_at=(datetime.utcnow() + timedelta(seconds=offset_seconds + 1)),
            status=status,
            run_kind="sync",
            byte_count=1024 if status == "ok" else None,
            package_count=8 if status == "ok" else None,
            manifest_sha256=manifest_sha if status == "ok" else None,
            manifest_path=(
                f"/snapshots/{counter['n']}.manifest.json" if status == "ok" else None
            ),
        )
        db.add(run)
        db.commit()
        db.refresh(run)
        return run

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
        db.commit()
        db.refresh(p)
        return p

    return make


@pytest.fixture
def channel_factory(db):
    counter = {"n": 0}

    def make(slug: str | None = None, package_family: str = "deb") -> ContentChannel:
        counter["n"] += 1
        slug = slug or f"chan-{counter['n']}"
        c = ContentChannel(
            slug=slug,
            display_name=slug,
            package_family=package_family,
        )
        db.add(c)
        db.commit()
        db.refresh(c)
        return c

    return make


def _link_profile_channel(db, profile: ContentProfile, channel: ContentChannel) -> None:
    db.add(ContentProfileChannel(profile_id=profile.id, channel_id=channel.id))
    db.commit()


def _link_channel_mirror(
    db,
    channel: ContentChannel,
    mirror: MirrorRepo,
    pinned_run_id: int | None = None,
) -> ContentChannelRepo:
    link = ContentChannelRepo(
        channel_id=channel.id,
        mirror_id=mirror.id,
        pinned_run_id=pinned_run_id,
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return link


def _add_signing_key(db, mirror: MirrorRepo, fingerprint: str) -> MirrorSigningKey:
    k = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status="active",
        gpg_fingerprint=fingerprint,
        key_uid=f"Praxis Mirror Signing {mirror.slug} {fingerprint}",
        vault_path=f"praxis/mirror-signing-keys/{mirror.slug}/{fingerprint}",
        armored_public_key="-----BEGIN PGP PUBLIC KEY BLOCK-----\n",
    )
    db.add(k)
    db.commit()
    db.refresh(k)
    return k


# ---------------------------------------------------------------------------
# Profile resolution
# ---------------------------------------------------------------------------


def test_unknown_profile_refuses(db):
    planner = AirgapPlanner(db)
    with pytest.raises(UnknownProfile) as exc_info:
        planner.plan(
            profile_slugs=["does-not-exist"],
            snapshot_selector_base="latest",
            snapshot_overrides=None,
            kind="full",
            parent_bundle_id=None,
            bundle_signing_fingerprint=_FPR,
        )
    assert exc_info.value.code == "unknown_profile"
    assert "does-not-exist" in exc_info.value.context["missing"]


def test_soft_deleted_profile_refuses(db, profile_factory):
    p = profile_factory("retired")
    p.deleted_at = datetime.utcnow()
    db.add(p)
    db.commit()
    planner = AirgapPlanner(db)
    with pytest.raises(UnknownProfile) as exc_info:
        planner.plan(
            profile_slugs=["retired"],
            snapshot_selector_base="latest",
            snapshot_overrides=None,
            kind="full",
            parent_bundle_id=None,
            bundle_signing_fingerprint=_FPR,
        )
    assert "retired" in exc_info.value.context["soft_deleted"]


def test_mixed_package_family_refuses(db, profile_factory):
    profile_factory("apt-prof", package_family="deb")
    profile_factory("dnf-prof", package_family="rpm")
    planner = AirgapPlanner(db)
    with pytest.raises(MixedPackageFamily) as exc_info:
        planner.plan(
            profile_slugs=["apt-prof", "dnf-prof"],
            snapshot_selector_base="latest",
            snapshot_overrides=None,
            kind="full",
            parent_bundle_id=None,
            bundle_signing_fingerprint=_FPR,
        )
    assert sorted(exc_info.value.context["families"]) == ["deb", "rpm"]


def test_delta_kind_with_unknown_parent_refuses(db, profile_factory):
    """Slice #4: kind='delta' is now implemented. With an unknown
    parent_bundle_id, the planner refuses DeltaParentMissing."""
    from app.services.airgap.planner import DeltaParentMissing

    profile_factory("p")
    planner = AirgapPlanner(db)
    with pytest.raises(DeltaParentMissing):
        planner.plan(
            profile_slugs=["p"],
            snapshot_selector_base="latest",
            snapshot_overrides=None,
            kind="delta",
            parent_bundle_id="00000000-0000-0000-0000-000000000000",
            bundle_signing_fingerprint=_FPR,
        )


# ---------------------------------------------------------------------------
# Mirror selection + happy path
# ---------------------------------------------------------------------------


def test_latest_happy_path_builds_descriptor(
    db,
    profile_factory,
    channel_factory,
    mirror_factory,
    run_factory,
):
    profile = profile_factory("prod-base")
    channel = channel_factory("base")
    mirror = mirror_factory(slug="ubuntu-jammy")
    _link_profile_channel(db, profile, channel)
    _link_channel_mirror(db, channel, mirror)
    run_factory(mirror, manifest_sha="a" * 64, offset_seconds=0)
    latest_run = run_factory(mirror, manifest_sha="b" * 64, offset_seconds=10)
    _add_signing_key(db, mirror, "BB" + "0" * 38)

    planner = AirgapPlanner(db)
    descriptor = planner.plan(
        profile_slugs=["prod-base"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        bundle_signing_fingerprint=_FPR,
    )

    assert descriptor.bundle_version == BUNDLE_SCHEMA_VERSION
    assert descriptor.kind == "full"
    assert descriptor.parent_bundle_id is None
    assert descriptor.praxis_instance_signing_fingerprint == _FPR
    assert len(descriptor.profiles) == 1
    assert descriptor.profiles[0].slug == "prod-base"
    assert descriptor.profiles[0].channel_slugs == ["base"]
    assert len(descriptor.channels) == 1
    assert descriptor.channels[0].slug == "base"
    assert descriptor.channels[0].repos[0].mirror_slug == "ubuntu-jammy"
    assert len(descriptor.mirrors) == 1
    mirror_desc = descriptor.mirrors[0]
    assert mirror_desc.mirror_slug == "ubuntu-jammy"
    assert mirror_desc.run_id == latest_run.id  # latest wins
    assert mirror_desc.manifest_sha256 == "b" * 64
    assert mirror_desc.signing_key_fingerprints == ["BB" + "0" * 38]
    assert descriptor.payload_index == []  # slice #1 leaves it empty


def test_pinned_base_canonicalizes_to_latest_when_byte_equivalent(
    db, profile_factory, channel_factory, mirror_factory, run_factory
):
    """Pinned run with matching manifest sha rewrites
    to latest-ok in the descriptor so imported provenance aligns with
    the live tree being exported."""
    profile = profile_factory("pinned-prof")
    channel = channel_factory("pinned-chan")
    mirror = mirror_factory(slug="ubuntu-pinned")
    pinned_run = run_factory(mirror, manifest_sha="c" * 64, offset_seconds=0)
    # Later no-op incremental sync produces an identical manifest sha.
    latest = run_factory(mirror, manifest_sha="c" * 64, offset_seconds=10)
    _link_profile_channel(db, profile, channel)
    _link_channel_mirror(db, channel, mirror, pinned_run_id=pinned_run.id)
    _add_signing_key(db, mirror, "AA" + "0" * 38)

    planner = AirgapPlanner(db)
    descriptor = planner.plan(
        profile_slugs=["pinned-prof"],
        snapshot_selector_base="pinned",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        bundle_signing_fingerprint=_FPR,
    )
    # Descriptor records the LIVE row id, not the original pin row.
    assert descriptor.mirrors[0].run_id == latest.id
    assert descriptor.mirrors[0].run_id != pinned_run.id


def test_pinned_base_uses_pin_directly_when_pin_is_latest(
    db, profile_factory, channel_factory, mirror_factory, run_factory
):
    """When the pinned row IS the latest-ok row, no rewrite needed."""
    profile = profile_factory("pinned-self")
    channel = channel_factory("pinned-self-chan")
    mirror = mirror_factory(slug="ubuntu-pinned-self")
    pinned_run = run_factory(mirror, manifest_sha="d" * 64, offset_seconds=0)
    _link_profile_channel(db, profile, channel)
    _link_channel_mirror(db, channel, mirror, pinned_run_id=pinned_run.id)
    _add_signing_key(db, mirror, "AD" + "0" * 38)

    planner = AirgapPlanner(db)
    descriptor = planner.plan(
        profile_slugs=["pinned-self"],
        snapshot_selector_base="pinned",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        bundle_signing_fingerprint=_FPR,
    )
    assert descriptor.mirrors[0].run_id == pinned_run.id


def test_pinned_base_with_no_pin_falls_back_to_latest(
    db, profile_factory, channel_factory, mirror_factory, run_factory
):
    """``base='pinned'`` + no channel pin set anywhere → latest-ok.
    This is fallback by absence-of-intent, not by silent downgrade
    from a missing/non-ok pin (which is now a refusal)."""
    profile = profile_factory("nopin-prof")
    channel = channel_factory("nopin-chan")
    mirror = mirror_factory(slug="ubuntu-nopin")
    _link_profile_channel(db, profile, channel)
    _link_channel_mirror(db, channel, mirror, pinned_run_id=None)
    latest = run_factory(mirror, manifest_sha="d" * 64, offset_seconds=10)
    _add_signing_key(db, mirror, "AB" + "0" * 38)

    planner = AirgapPlanner(db)
    descriptor = planner.plan(
        profile_slugs=["nopin-prof"],
        snapshot_selector_base="pinned",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        bundle_signing_fingerprint=_FPR,
    )
    assert descriptor.mirrors[0].run_id == latest.id


def test_explicit_override_is_honored_and_canonicalizes(
    db, profile_factory, channel_factory, mirror_factory, run_factory
):
    """Explicit override that's byte-equivalent to
    latest also gets rewritten to latest's run id."""
    profile = profile_factory("ov-prof")
    channel = channel_factory("ov-chan")
    mirror = mirror_factory(slug="ubuntu-override")
    explicit = run_factory(mirror, manifest_sha="e" * 64, offset_seconds=0)
    # No-op incremental keeps explicit byte-equivalent to latest.
    latest = run_factory(mirror, manifest_sha="e" * 64, offset_seconds=10)
    _link_profile_channel(db, profile, channel)
    _link_channel_mirror(db, channel, mirror)
    _add_signing_key(db, mirror, "AC" + "0" * 38)

    planner = AirgapPlanner(db)
    descriptor = planner.plan(
        profile_slugs=["ov-prof"],
        snapshot_selector_base="latest",
        snapshot_overrides={"ubuntu-override": explicit.id},
        kind="full",
        parent_bundle_id=None,
        bundle_signing_fingerprint=_FPR,
    )
    # Override accepted and byte-validated; descriptor reflects the
    # live row id, not the historical override row.
    assert descriptor.mirrors[0].run_id == latest.id


def test_explicit_override_when_already_latest(
    db, profile_factory, channel_factory, mirror_factory, run_factory
):
    """Override pointing at the latest-ok row is honored as-is."""
    profile = profile_factory("ov2")
    channel = channel_factory("ov2-chan")
    mirror = mirror_factory(slug="ubuntu-ov2")
    explicit = run_factory(mirror, manifest_sha="ee" + "e" * 62, offset_seconds=0)
    _link_profile_channel(db, profile, channel)
    _link_channel_mirror(db, channel, mirror)
    _add_signing_key(db, mirror, "AE" + "0" * 38)

    planner = AirgapPlanner(db)
    descriptor = planner.plan(
        profile_slugs=["ov2"],
        snapshot_selector_base="latest",
        snapshot_overrides={"ubuntu-ov2": explicit.id},
        kind="full",
        parent_bundle_id=None,
        bundle_signing_fingerprint=_FPR,
    )
    assert descriptor.mirrors[0].run_id == explicit.id


def test_override_for_unscoped_mirror_refuses(
    db, profile_factory, channel_factory, mirror_factory, run_factory
):
    profile = profile_factory("only")
    channel = channel_factory("only-chan")
    mirror_in_scope = mirror_factory(slug="in-scope")
    _link_profile_channel(db, profile, channel)
    _link_channel_mirror(db, channel, mirror_in_scope)
    run_factory(mirror_in_scope, manifest_sha="f" * 64, offset_seconds=0)

    planner = AirgapPlanner(db)
    with pytest.raises(UnknownOverrideMirror) as exc_info:
        planner.plan(
            profile_slugs=["only"],
            snapshot_selector_base="latest",
            snapshot_overrides={"not-in-any-channel": 1},
            kind="full",
            parent_bundle_id=None,
            bundle_signing_fingerprint=_FPR,
        )
    assert exc_info.value.context["override_slug"] == "not-in-any-channel"


def test_override_run_with_wrong_status_refuses(
    db, profile_factory, channel_factory, mirror_factory, run_factory
):
    profile = profile_factory("p")
    channel = channel_factory("c")
    mirror = mirror_factory(slug="mfailed")
    _link_profile_channel(db, profile, channel)
    _link_channel_mirror(db, channel, mirror)
    run_factory(mirror, manifest_sha="g" * 64, offset_seconds=0)
    failed = run_factory(mirror, manifest_sha="x", status="failed")

    planner = AirgapPlanner(db)
    with pytest.raises(InvalidOverrideRun):
        planner.plan(
            profile_slugs=["p"],
            snapshot_selector_base="latest",
            snapshot_overrides={"mfailed": failed.id},
            kind="full",
            parent_bundle_id=None,
            bundle_signing_fingerprint=_FPR,
        )


# ---------------------------------------------------------------------------
# Critical: byte-match validation
# ---------------------------------------------------------------------------


def test_explicit_override_with_stale_bytes_refuses(
    db, profile_factory, channel_factory, mirror_factory, run_factory
):
    """Operator picks an older run whose manifest_sha differs from
    the latest-ok run. PRA-157 doesn't keep historical bytes →
    refuse. This is the slice #1 critical lock."""
    profile = profile_factory("p")
    channel = channel_factory("c")
    mirror = mirror_factory(slug="mstale")
    older = run_factory(mirror, manifest_sha="0" * 64, offset_seconds=0)
    run_factory(mirror, manifest_sha="1" * 64, offset_seconds=10)  # newer/live
    _link_profile_channel(db, profile, channel)
    _link_channel_mirror(db, channel, mirror)

    planner = AirgapPlanner(db)
    with pytest.raises(HistoricalBytesUnavailable) as exc_info:
        planner.plan(
            profile_slugs=["p"],
            snapshot_selector_base="latest",
            snapshot_overrides={"mstale": older.id},
            kind="full",
            parent_bundle_id=None,
            bundle_signing_fingerprint=_FPR,
        )
    ctx = exc_info.value.context
    assert ctx["mirror_slug"] == "mstale"
    assert ctx["requested_run_id"] == older.id
    assert ctx["requested_manifest_sha256"] == "0" * 64
    assert ctx["current_live_manifest_sha256"] == "1" * 64


def test_pinned_with_stale_bytes_refuses(
    db, profile_factory, channel_factory, mirror_factory, run_factory
):
    """Channel pin points at a run whose bytes are no longer live."""
    profile = profile_factory("p")
    channel = channel_factory("c")
    mirror = mirror_factory(slug="mpinstale")
    pinned_run = run_factory(mirror, manifest_sha="2" * 64, offset_seconds=0)
    run_factory(mirror, manifest_sha="3" * 64, offset_seconds=10)
    _link_profile_channel(db, profile, channel)
    _link_channel_mirror(db, channel, mirror, pinned_run_id=pinned_run.id)

    planner = AirgapPlanner(db)
    with pytest.raises(HistoricalBytesUnavailable):
        planner.plan(
            profile_slugs=["p"],
            snapshot_selector_base="pinned",
            snapshot_overrides=None,
            kind="full",
            parent_bundle_id=None,
            bundle_signing_fingerprint=_FPR,
        )


def test_no_snapshot_available_refuses(
    db, profile_factory, channel_factory, mirror_factory
):
    """Mirror has no status='ok' runs at all."""
    profile = profile_factory("p")
    channel = channel_factory("c")
    mirror = mirror_factory(slug="never-synced")
    _link_profile_channel(db, profile, channel)
    _link_channel_mirror(db, channel, mirror)

    planner = AirgapPlanner(db)
    with pytest.raises(NoSnapshotAvailable):
        planner.plan(
            profile_slugs=["p"],
            snapshot_selector_base="latest",
            snapshot_overrides=None,
            kind="full",
            parent_bundle_id=None,
            bundle_signing_fingerprint=_FPR,
        )


def test_empty_profile_refuses(db, profile_factory):
    """Profile exists but has no channels (and therefore no mirror entries)."""
    profile_factory("hollow")
    planner = AirgapPlanner(db)
    with pytest.raises(EmptyProfile):
        planner.plan(
            profile_slugs=["hollow"],
            snapshot_selector_base="latest",
            snapshot_overrides=None,
            kind="full",
            parent_bundle_id=None,
            bundle_signing_fingerprint=_FPR,
        )


# ---------------------------------------------------------------------------
# PinUnusable / ConflictingPins / MirrorSigningMaterialMissing
# ---------------------------------------------------------------------------


def test_pinned_run_with_failed_status_refuses_with_pin_unusable(
    db, profile_factory, channel_factory, mirror_factory, run_factory
):
    """Channel pin points at a non-ok run row → PinUnusable, not silent
    fallback to latest."""
    profile = profile_factory("p")
    channel = channel_factory("c")
    mirror = mirror_factory(slug="m-pin-failed")
    failed_pin = run_factory(mirror, manifest_sha="x", status="failed")
    run_factory(mirror, manifest_sha="y" * 64, offset_seconds=10)
    _link_profile_channel(db, profile, channel)
    _link_channel_mirror(db, channel, mirror, pinned_run_id=failed_pin.id)
    _add_signing_key(db, mirror, "AF" + "0" * 38)

    planner = AirgapPlanner(db)
    with pytest.raises(PinUnusable) as exc_info:
        planner.plan(
            profile_slugs=["p"],
            snapshot_selector_base="pinned",
            snapshot_overrides=None,
            kind="full",
            parent_bundle_id=None,
            bundle_signing_fingerprint=_FPR,
        )
    assert exc_info.value.context["mirror_slug"] == "m-pin-failed"
    assert exc_info.value.context["pinned_run_id"] == failed_pin.id
    assert exc_info.value.context["reason"] == "pin_run_not_ok"


# Note: a "missing pin run row" case is structurally unreachable —
# content_channel_repos.pinned_run_id is ON DELETE SET NULL, so a
# vanished run row null-out the pin instead of leaving a dangling
# reference. The defensive `run is None` branch in
# ``_select_run_for_mirror`` is insurance only.


def test_conflicting_pins_per_mirror_refuses(
    db, profile_factory, channel_factory, mirror_factory, run_factory
):
    """Two channels in scope pin the same mirror to runs with
    different manifest sha256 values → ConflictingPins."""
    profile = profile_factory("conflict-prof")
    chan_a = channel_factory("conflict-a")
    chan_b = channel_factory("conflict-b")
    mirror = mirror_factory(slug="m-conflict")
    pin_a = run_factory(mirror, manifest_sha="11" + "1" * 62, offset_seconds=0)
    pin_b = run_factory(mirror, manifest_sha="22" + "2" * 62, offset_seconds=10)
    _link_profile_channel(db, profile, chan_a)
    _link_profile_channel(db, profile, chan_b)
    _link_channel_mirror(db, chan_a, mirror, pinned_run_id=pin_a.id)
    _link_channel_mirror(db, chan_b, mirror, pinned_run_id=pin_b.id)
    _add_signing_key(db, mirror, "B1" + "0" * 38)

    planner = AirgapPlanner(db)
    with pytest.raises(ConflictingPins) as exc_info:
        planner.plan(
            profile_slugs=["conflict-prof"],
            snapshot_selector_base="pinned",
            snapshot_overrides=None,
            kind="full",
            parent_bundle_id=None,
            bundle_signing_fingerprint=_FPR,
        )
    ctx = exc_info.value.context
    assert ctx["mirror_slug"] == "m-conflict"
    assert ctx["distinct_manifest_sha256_count"] == 2
    assert sorted(ctx["pinned_run_ids"]) == sorted([pin_a.id, pin_b.id])


def test_conflicting_pins_with_same_sha_does_not_refuse(
    db, profile_factory, channel_factory, mirror_factory, run_factory
):
    """Two channels pin the same mirror to different run rows but
    same manifest_sha256 — byte-equivalent, so accepted (and
    canonicalized to latest by Q3 logic)."""
    profile = profile_factory("eq-prof")
    chan_a = channel_factory("eq-a")
    chan_b = channel_factory("eq-b")
    mirror = mirror_factory(slug="m-eq")
    pin_a = run_factory(mirror, manifest_sha="33" + "3" * 62, offset_seconds=0)
    pin_b = run_factory(mirror, manifest_sha="33" + "3" * 62, offset_seconds=10)
    _link_profile_channel(db, profile, chan_a)
    _link_profile_channel(db, profile, chan_b)
    _link_channel_mirror(db, chan_a, mirror, pinned_run_id=pin_a.id)
    _link_channel_mirror(db, chan_b, mirror, pinned_run_id=pin_b.id)
    _add_signing_key(db, mirror, "B2" + "0" * 38)

    planner = AirgapPlanner(db)
    descriptor = planner.plan(
        profile_slugs=["eq-prof"],
        snapshot_selector_base="pinned",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        bundle_signing_fingerprint=_FPR,
    )
    # Equivalent shas → planner picks one, then byte-match validator
    # canonicalizes to latest.
    assert descriptor.mirrors[0].run_id == pin_b.id


def test_mirror_with_no_armored_signing_keys_refuses(
    db, profile_factory, channel_factory, mirror_factory, run_factory
):
    """Mirror in scope has signing key rows but none
    carry armored_public_key bytes → refuse rather than ship a
    signed-but-unverifiable bundle."""
    profile = profile_factory("p")
    channel = channel_factory("c")
    mirror = mirror_factory(slug="m-no-armor")
    _link_profile_channel(db, profile, channel)
    _link_channel_mirror(db, channel, mirror)
    run_factory(mirror, manifest_sha="44" + "4" * 62, offset_seconds=0)
    # Add a signing key row whose armored_public_key is None.
    k = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status="active",
        gpg_fingerprint="C0" + "0" * 38,
        key_uid="legacy",
        vault_path="praxis/mirror-signing-keys/m-no-armor/legacy",
        armored_public_key=None,
    )
    db.add(k)
    db.commit()

    planner = AirgapPlanner(db)
    with pytest.raises(MirrorSigningMaterialMissing) as exc_info:
        planner.plan(
            profile_slugs=["p"],
            snapshot_selector_base="latest",
            snapshot_overrides=None,
            kind="full",
            parent_bundle_id=None,
            bundle_signing_fingerprint=_FPR,
        )
    assert exc_info.value.context["mirror_slug"] == "m-no-armor"


def test_mirror_with_no_signing_keys_at_all_refuses(
    db, profile_factory, channel_factory, mirror_factory, run_factory
):
    """No signing-key rows of any kind → also refuses."""
    profile = profile_factory("p")
    channel = channel_factory("c")
    mirror = mirror_factory(slug="m-no-key")
    _link_profile_channel(db, profile, channel)
    _link_channel_mirror(db, channel, mirror)
    run_factory(mirror, manifest_sha="55" + "5" * 62, offset_seconds=0)
    # Intentionally no _add_signing_key call.

    planner = AirgapPlanner(db)
    with pytest.raises(MirrorSigningMaterialMissing):
        planner.plan(
            profile_slugs=["p"],
            snapshot_selector_base="latest",
            snapshot_overrides=None,
            kind="full",
            parent_bundle_id=None,
            bundle_signing_fingerprint=_FPR,
        )


def test_equal_sha_pins_with_one_failed_pin_refuses(
    db, profile_factory, channel_factory, mirror_factory, run_factory
):
    """When multiple pins for one mirror collapse to
    the same manifest sha, EVERY pin must still reference an ok run.
    A failed pin in the set must be caught BEFORE the equal-sha
    conflict logic picks a winner."""
    profile = profile_factory("eqfail")
    chan_a = channel_factory("eqfail-a")
    chan_b = channel_factory("eqfail-b")
    mirror = mirror_factory(slug="m-eqfail")
    pin_ok = run_factory(mirror, manifest_sha="77" + "7" * 62, offset_seconds=0)
    # A "failed" pin still references the same mirror; failed runs
    # have no manifest_sha256 — so they're not part of sha conflict
    # detection and would silently slip through without per-pin
    # validation.
    pin_failed = run_factory(mirror, manifest_sha="x", status="failed")
    _link_profile_channel(db, profile, chan_a)
    _link_profile_channel(db, profile, chan_b)
    _link_channel_mirror(db, chan_a, mirror, pinned_run_id=pin_ok.id)
    _link_channel_mirror(db, chan_b, mirror, pinned_run_id=pin_failed.id)
    _add_signing_key(db, mirror, "BB" + "1" * 38)

    planner = AirgapPlanner(db)
    with pytest.raises(PinUnusable) as exc_info:
        planner.plan(
            profile_slugs=["eqfail"],
            snapshot_selector_base="pinned",
            snapshot_overrides=None,
            kind="full",
            parent_bundle_id=None,
            bundle_signing_fingerprint=_FPR,
        )
    assert exc_info.value.context["pinned_run_id"] == pin_failed.id
    assert exc_info.value.context["reason"] == "pin_run_not_ok"


def test_pinned_run_owned_by_other_mirror_refuses(
    db, profile_factory, channel_factory, mirror_factory, run_factory
):
    """Planner is the final airgap trust gate. A
    channel pinned_run_id pointing at an ok run from a DIFFERENT
    mirror must refuse loudly even if the API normally prevents it
    (stale rows, manual edits, future schema-behavior drift)."""
    profile = profile_factory("p")
    channel = channel_factory("c")
    mirror_a = mirror_factory(slug="m-a-cross")
    mirror_b = mirror_factory(slug="m-b-cross")
    # Run belongs to mirror_b but is referenced as a pin from
    # mirror_a's channel.
    foreign_run = run_factory(mirror_b, manifest_sha="99" + "9" * 62, offset_seconds=0)
    run_factory(mirror_a, manifest_sha="aa" + "a" * 62, offset_seconds=0)
    _link_profile_channel(db, profile, channel)
    # Bypass any service-side validation by writing the FK link
    # directly.
    _link_channel_mirror(db, channel, mirror_a, pinned_run_id=foreign_run.id)
    _add_signing_key(db, mirror_a, "C0" + "0" * 38)

    planner = AirgapPlanner(db)
    with pytest.raises(PinUnusable) as exc_info:
        planner.plan(
            profile_slugs=["p"],
            snapshot_selector_base="pinned",
            snapshot_overrides=None,
            kind="full",
            parent_bundle_id=None,
            bundle_signing_fingerprint=_FPR,
        )
    ctx = exc_info.value.context
    assert ctx["reason"] == "pin_run_wrong_mirror"
    assert ctx["mirror_slug"] == "m-a-cross"
    assert ctx["pinned_run_id"] == foreign_run.id
    assert ctx["pin_mirror_repo_id"] == mirror_b.id
    assert ctx["expected_mirror_repo_id"] == mirror_a.id


def test_equal_sha_pins_picks_most_recent_ok(
    db, profile_factory, channel_factory, mirror_factory, run_factory
):
    """Equal-sha pins pick the most-recent ok row
    by ``started_at`` (closest to live)."""
    profile = profile_factory("recent")
    chan_a = channel_factory("recent-a")
    chan_b = channel_factory("recent-b")
    mirror = mirror_factory(slug="m-recent")
    older = run_factory(mirror, manifest_sha="88" + "8" * 62, offset_seconds=0)
    newer = run_factory(mirror, manifest_sha="88" + "8" * 62, offset_seconds=20)
    _link_profile_channel(db, profile, chan_a)
    _link_profile_channel(db, profile, chan_b)
    _link_channel_mirror(db, chan_a, mirror, pinned_run_id=older.id)
    _link_channel_mirror(db, chan_b, mirror, pinned_run_id=newer.id)
    _add_signing_key(db, mirror, "BC" + "1" * 38)

    planner = AirgapPlanner(db)
    descriptor = planner.plan(
        profile_slugs=["recent"],
        snapshot_selector_base="pinned",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        bundle_signing_fingerprint=_FPR,
    )
    # Most-recent ok pin is ``newer`` (offset 20 > 0). Canonicalizer
    # keeps it as latest-ok (which is also ``newer`` since it's the
    # last sync).
    assert descriptor.mirrors[0].run_id == newer.id
