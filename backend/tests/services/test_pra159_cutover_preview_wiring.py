"""PRA-159 #4: cutover_preview wiring tests.

Asserts the previously-empty buckets (hosts_never_installed,
hosts_stale_trust_record) are populated from the host → effective
profile → channel → mirror chain.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock

import pytest

from app.db.models import (
    ContentChannel,
    ContentChannelRepo,
    ContentProfile,
    ContentProfileChannel,
    Credential,
    Group,
    HostContentProfileSubscription,
    HostMirrorTrust,
    MirrorRepo,
    MirrorSigningKey,
    System,
)
from app.services.mirror_signing_key_service import (
    MirrorSigningKeyService,
    vault_path_for,
)

_ACTIVE_FPR = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
_PENDING_FPR = "B" * 40


@pytest.fixture
def patch_gpg(monkeypatch):
    """Stub the GPG fingerprint extraction so ensure_active +
    rotate_prepare can run without real gpg subprocesses (mirrors
    the PRA-158 test pattern)."""
    from app.services import mirror_gpg

    counter = {"n": 0}

    def fake_generate(uid):  # noqa: ARG001
        counter["n"] += 1
        if counter["n"] == 1:
            fp = _ACTIVE_FPR
        else:
            fp = _PENDING_FPR
        armored_pub = (
            f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-PUB-{fp}\n-----END-----\n"
        )
        armored_priv = (
            f"-----BEGIN PGP PRIVATE KEY BLOCK-----\nFAKE-PRIV-{fp}\n-----END-----\n"
        )
        return mirror_gpg.GeneratedKey(
            fingerprint=fp,
            uid=uid,
            armored_public=armored_pub,
            armored_private=armored_priv,
        )

    monkeypatch.setattr(mirror_gpg, "generate_key", fake_generate)


@pytest.fixture
def mirror(db) -> MirrorRepo:
    m = MirrorRepo(
        slug="cutover-mirror",
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


def _seed_active_pending(db, mirror):
    """Insert active + pending_cutover signing keys directly so we
    don't need a real Vault round-trip in the cutover-preview tests."""
    for status, fpr in (("active", _ACTIVE_FPR), ("pending_cutover", _PENDING_FPR)):
        db.add(
            MirrorSigningKey(
                mirror_repo_id=mirror.id,
                status=status,
                gpg_fingerprint=fpr,
                key_uid=f"Praxis Mirror {mirror.slug} {status}",
                vault_path=vault_path_for(mirror.slug, fpr),
                armored_public_key=f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-{status}\n-----END-----\n",
            )
        )
    db.commit()


def _make_host(db, seed_distro, hostname: str) -> System:
    g = Group(name=f"cv-grp-{hostname}")
    db.add(g)
    db.flush()
    cred = Credential(
        name=f"cv-cred-{hostname}", auth_method="ssh_key", username="root"
    )
    db.add(cred)
    db.flush()
    s = System(
        hostname=hostname,
        ip_address="10.81.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.commit()
    return s


def _bind_host_to_profile_with_mirror(db, host, mirror):
    chan = ContentChannel(
        slug=f"cv-chan-{host.hostname}", display_name="x", package_family="deb"
    )
    db.add(chan)
    db.flush()
    db.add(ContentChannelRepo(channel_id=chan.id, mirror_id=mirror.id))
    profile = ContentProfile(
        slug=f"cv-prof-{host.hostname}", display_name="x", package_family="deb"
    )
    db.add(profile)
    db.flush()
    db.add(ContentProfileChannel(profile_id=profile.id, channel_id=chan.id))
    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=profile.id))
    db.commit()


def test_hosts_never_installed_populated(db, mirror, seed_distro):
    """A host whose effective profile composes the rotating mirror
    but has NO host_mirror_trust row lands in hosts_never_installed."""
    _seed_active_pending(db, mirror)
    h = _make_host(db, seed_distro, "never-installed.example.com")
    _bind_host_to_profile_with_mirror(db, h, mirror)

    preview = MirrorSigningKeyService(db).cutover_preview(mirror.id)
    assert preview["pending_fingerprint"] == _PENDING_FPR
    assert preview["hosts_never_installed"] == [h.id]
    # No trust row → not in stale or missing-pending either.
    assert preview["hosts_missing_pending"] == []
    assert preview["hosts_stale_trust_record"] == []


def test_hosts_stale_trust_record_populated(db, mirror, seed_distro):
    """A subscribed host with a trust row whose installed set is
    missing the active fingerprint lands in hosts_stale_trust_record."""
    _seed_active_pending(db, mirror)
    h = _make_host(db, seed_distro, "stale-trust.example.com")
    _bind_host_to_profile_with_mirror(db, h, mirror)
    db.add(
        HostMirrorTrust(
            host_id=h.id,
            mirror_id=mirror.id,
            installed_fingerprints=["DEADBEEF" * 5],  # not the active fp
            last_installed_at=datetime.utcnow(),
        )
    )
    db.commit()

    preview = MirrorSigningKeyService(db).cutover_preview(mirror.id)
    assert preview["hosts_stale_trust_record"] == [h.id]
    # Trust row exists but is missing pending too — also flagged in
    # the historical bucket.
    assert h.id in preview["hosts_missing_pending"]
    assert preview["hosts_never_installed"] == []


def test_unsubscribed_hosts_excluded_from_new_buckets(db, mirror, seed_distro):
    """A host with no profile subscription to a channel including the
    rotating mirror does NOT show up in either new bucket, even when
    it has a trust row that's missing pending."""
    _seed_active_pending(db, mirror)
    h = _make_host(db, seed_distro, "unsubscribed.example.com")
    db.add(
        HostMirrorTrust(
            host_id=h.id,
            mirror_id=mirror.id,
            installed_fingerprints=[_ACTIVE_FPR],  # missing pending
            last_installed_at=datetime.utcnow(),
        )
    )
    db.commit()

    preview = MirrorSigningKeyService(db).cutover_preview(mirror.id)
    # missing_pending still flags this host (PRA-158 contract — they
    # explicitly opted into trust, so cutover concerns them).
    assert preview["hosts_missing_pending"] == [h.id]
    # But the new buckets are subscription-scoped and unsubscribed
    # hosts have no effective profile → excluded.
    assert preview["hosts_never_installed"] == []
    assert preview["hosts_stale_trust_record"] == []


def test_resolved_subscriber_with_full_trust_is_clean(db, mirror, seed_distro):
    """A subscribed host with both active + pending fingerprints
    installed lands in NO bucket — apply orchestrator + manual
    install have already handled it."""
    _seed_active_pending(db, mirror)
    h = _make_host(db, seed_distro, "clean.example.com")
    _bind_host_to_profile_with_mirror(db, h, mirror)
    db.add(
        HostMirrorTrust(
            host_id=h.id,
            mirror_id=mirror.id,
            installed_fingerprints=[_ACTIVE_FPR, _PENDING_FPR],
            last_installed_at=datetime.utcnow(),
        )
    )
    db.commit()

    preview = MirrorSigningKeyService(db).cutover_preview(mirror.id)
    assert preview["hosts_missing_pending"] == []
    assert preview["hosts_never_installed"] == []
    assert preview["hosts_stale_trust_record"] == []
