"""PRA-159 #3: apply_content_profile_to_host orchestrator tests.

Mocked-transport coverage of the full apply sequence:
  * refused_no_profile / refused_conflict → no /etc writes
  * resolved → trust install + cred issue + write + remove obsolete
  * idempotent re-apply (no-op when nothing changes besides the
    cred rotation that always happens)
  * trust install failure short-circuits
  * write failure leaves earlier writes in place
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

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
from app.services.content_profile_apply import apply_content_profile_to_host
from app.services.mirror_signing_key_service import vault_path_for

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="apply-grp")
    db.add(g)
    db.flush()
    cred = Credential(name="apply-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    s = System(
        hostname="apply-host.example.com",
        ip_address="10.70.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.commit()
    return s


def _make_mirror(db, slug="apply-mirror", family="deb", suite="jammy"):
    m = MirrorRepo(
        slug=slug,
        display_name=slug,
        package_family=family,
        upstream_url="http://x/y",
        distribution=suite,
        components='["main"]' if family == "deb" else "[]",
        architectures='["amd64"]' if family == "deb" else '["x86_64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(m)
    db.flush()
    return m


def _add_signing_key(db, mirror, fpr):
    """Active key + cached armored public so install_mirror_trust
    doesn't need Vault."""
    armored = f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-{fpr}\n-----END-----\n"
    row = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status="active",
        gpg_fingerprint=fpr,
        key_uid=f"Praxis Mirror {mirror.slug}",
        vault_path=vault_path_for(mirror.slug, fpr),
        armored_public_key=armored,
    )
    db.add(row)
    db.commit()
    return row


def _bind_profile_to_host(db, host, mirror, *, slug="prod"):
    channel = ContentChannel(slug=f"{slug}-c", display_name="x", package_family="deb")
    db.add(channel)
    db.flush()
    db.add(ContentChannelRepo(channel_id=channel.id, mirror_id=mirror.id))

    profile = ContentProfile(slug=slug, display_name=slug, package_family="deb")
    db.add(profile)
    db.flush()
    db.add(ContentProfileChannel(profile_id=profile.id, channel_id=channel.id))
    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=profile.id))
    db.commit()
    return profile, channel


def _fake_transport(name="ssh", *, run_outcomes=None, list_outputs=None):
    """Mock transport. ``list_outputs`` is queued up for sh -c ls calls
    (``sh`` argv); other calls fall through to ``run_outcomes`` /
    success default."""
    t = MagicMock()
    t.name = name
    calls: list = []
    out_q = list(run_outcomes or [])
    list_q = list(list_outputs or [])

    async def _run(argv, *, stdin=None, timeout_seconds=None):
        calls.append({"argv": list(argv), "stdin": stdin})
        if argv and len(argv) >= 4 and argv[2] == "sh" and argv[3] == "-c":
            # list_managed_files path: pop next listing.
            if list_q:
                return list_q.pop(0)
            return MagicMock(exit_code=0, stderr=b"", stdout=b"")
        if out_q:
            return out_q.pop(0)
        return MagicMock(exit_code=0, stderr=b"", stdout=b"")

    t.run_command = _run
    t._calls = calls
    return t


# ---------------------------------------------------------------------------
# Refusal paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_apply_refused_no_profile(db, host):
    transport = _fake_transport()
    outcome = await apply_content_profile_to_host(db, host, transport)
    assert outcome.state == "refused_no_profile"
    # No transport calls — Praxis must not touch /etc when the host
    # has no effective profile.
    assert transport._calls == []


@pytest.mark.asyncio
async def test_apply_refused_conflict(db, host):
    p1 = ContentProfile(slug="conf-1", display_name="x", package_family="deb")
    p2 = ContentProfile(slug="conf-2", display_name="x", package_family="deb")
    db.add_all([p1, p2])
    db.flush()
    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=p1.id))
    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=p2.id))
    db.commit()

    transport = _fake_transport()
    outcome = await apply_content_profile_to_host(db, host, transport)
    assert outcome.state == "refused_conflict"
    assert transport._calls == []


# ---------------------------------------------------------------------------
# Resolved happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_apply_resolved_writes_profile_files(db, host):
    mirror = _make_mirror(db)
    _add_signing_key(db, mirror, fpr="A" * 40)
    profile, _ = _bind_profile_to_host(db, host, mirror)

    transport = _fake_transport(
        list_outputs=[
            # /etc/apt/sources.list.d listing — empty
            MagicMock(exit_code=0, stderr=b"", stdout=b""),
            # /etc/apt/auth.conf.d listing — empty
            MagicMock(exit_code=0, stderr=b"", stdout=b""),
        ]
    )

    outcome = await apply_content_profile_to_host(
        db, host, transport, serve_base_url="https://praxis.example.com"
    )

    assert outcome.state == "applied", outcome.error_text
    assert outcome.profile_slug == "prod"
    # Trust install ran for the one mirror
    assert outcome.trust_installed_for_mirrors == [mirror.slug]
    # One credential issued for that mirror
    assert outcome.credentials_issued_for_mirrors == [mirror.slug]
    # Two files written: .list + .conf
    assert sorted(outcome.written_paths) == [
        "/etc/apt/auth.conf.d/praxis-profile-prod.conf",
        "/etc/apt/sources.list.d/praxis-profile-prod.list",
    ]
    assert outcome.removed_paths == []


@pytest.mark.asyncio
async def test_apply_resolved_skips_trust_install_when_already_installed(db, host):
    mirror = _make_mirror(db)
    fpr = "A" * 40
    _add_signing_key(db, mirror, fpr=fpr)
    profile, _ = _bind_profile_to_host(db, host, mirror)

    # Pre-seed host_mirror_trust with the active fingerprint.
    db.add(
        HostMirrorTrust(
            host_id=host.id,
            mirror_id=mirror.id,
            installed_fingerprints=[fpr],
            last_installed_at=datetime.utcnow(),
        )
    )
    db.commit()

    transport = _fake_transport(
        list_outputs=[
            MagicMock(exit_code=0, stderr=b"", stdout=b""),
            MagicMock(exit_code=0, stderr=b"", stdout=b""),
        ]
    )

    outcome = await apply_content_profile_to_host(
        db, host, transport, serve_base_url="https://praxis.example.com"
    )
    assert outcome.state == "applied"
    # Trust install SKIPPED because installed_fingerprints already
    # contains the active fingerprint.
    assert outcome.trust_installed_for_mirrors == []
    # Credentials still rotated on every apply.
    assert outcome.credentials_issued_for_mirrors == [mirror.slug]


@pytest.mark.asyncio
async def test_apply_removes_obsolete_managed_files(db, host):
    """A praxis-profile-* file from a prior profile binding that's no
    longer in the desired set must be removed."""
    mirror = _make_mirror(db)
    _add_signing_key(db, mirror, fpr="A" * 40)
    profile, _ = _bind_profile_to_host(db, host, mirror, slug="prod")

    # On-host listing returns an obsolete file (from a hypothetical
    # prior "stage" profile binding).
    obsolete = "/etc/apt/sources.list.d/praxis-profile-stage.list"
    transport = _fake_transport(
        list_outputs=[
            MagicMock(
                exit_code=0,
                stderr=b"",
                stdout=(obsolete + "\n").encode("utf-8"),
            ),
            MagicMock(exit_code=0, stderr=b"", stdout=b""),
        ]
    )

    outcome = await apply_content_profile_to_host(
        db, host, transport, serve_base_url="https://x.com"
    )
    assert outcome.state == "applied"
    assert obsolete in outcome.removed_paths
    # The obsolete file rm command was issued.
    rm_cmds = [
        c for c in transport._calls if "rm" in c["argv"] and obsolete in c["argv"]
    ]
    assert len(rm_cmds) == 1


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_apply_bails_on_trust_install_failure(db, host, monkeypatch):
    mirror = _make_mirror(db)
    _add_signing_key(db, mirror, fpr="A" * 40)
    _bind_profile_to_host(db, host, mirror)

    # Stub install_mirror_trust_on_host to fail.
    from app.services import content_profile_apply as orch_module
    from app.services.mirror_host_trust import HostInstallResult

    async def _fail(*_a, **_k):
        return HostInstallResult(
            host_id=host.id,
            ok=False,
            installed_fingerprints=[],
            written_paths=[],
            error_text="sudo: a password is required",
        )

    monkeypatch.setattr(orch_module, "install_mirror_trust_on_host", _fail)

    transport = _fake_transport()
    outcome = await apply_content_profile_to_host(
        db, host, transport, serve_base_url="https://x.com"
    )
    assert outcome.state == "failed"
    assert "trust install failed" in outcome.error_text
    assert "sudo: a password is required" in outcome.error_text
    # No files written — bail short-circuited.
    assert outcome.written_paths == []


@pytest.mark.asyncio
async def test_apply_failed_when_public_url_unset(db, host, monkeypatch):
    """The orchestrator refuses to write host config when
    PRAXIS_PUBLIC_URL is unset. Refusal
    happens AFTER resolution so this requires a resolved profile."""
    monkeypatch.delenv("PRAXIS_PUBLIC_URL", raising=False)
    mirror = _make_mirror(db)
    _add_signing_key(db, mirror, fpr="A" * 40)
    _bind_profile_to_host(db, host, mirror)

    transport = _fake_transport()
    # No serve_base_url passed → falls through to public_serve_base_url()
    outcome = await apply_content_profile_to_host(db, host, transport)
    assert outcome.state == "failed"
    assert "PRAXIS_PUBLIC_URL" in outcome.error_text


@pytest.mark.asyncio
async def test_apply_defers_revoke_until_writes_succeed(db, host):
    """Slice #3 P2: a prior credential remains active during the
    write window so the host's last-good package access is preserved
    if anything fails. After successful writes the orchestrator
    revokes the prior cred."""
    from app.db.models import HostMirrorServeCredential
    from app.services.mirror_serve_credential_service import (
        MirrorServeCredentialService,
    )

    mirror = _make_mirror(db)
    _add_signing_key(db, mirror, fpr="A" * 40)
    _bind_profile_to_host(db, host, mirror)

    # Pre-seed a prior active credential so the orchestrator has
    # something to revoke.
    cred_svc = MirrorServeCredentialService(db)
    prior = cred_svc.issue(host_id=host.id, mirror_id=mirror.id)
    prior_id = prior.credential_id

    transport = _fake_transport(
        list_outputs=[
            MagicMock(exit_code=0, stderr=b"", stdout=b""),
            MagicMock(exit_code=0, stderr=b"", stdout=b""),
        ]
    )
    outcome = await apply_content_profile_to_host(
        db, host, transport, serve_base_url="https://x.com"
    )
    assert outcome.state == "applied"

    # Prior credential is now revoked; new credential is active.
    prior_row = (
        db.query(HostMirrorServeCredential)
        .filter(HostMirrorServeCredential.id == prior_id)
        .one()
    )
    assert prior_row.revoked_at is not None
    active_after = (
        db.query(HostMirrorServeCredential)
        .filter(
            HostMirrorServeCredential.host_id == host.id,
            HostMirrorServeCredential.mirror_id == mirror.id,
            HostMirrorServeCredential.revoked_at.is_(None),
        )
        .all()
    )
    assert len(active_after) == 1
    assert active_after[0].id != prior_id


@pytest.mark.asyncio
async def test_apply_keeps_prior_active_when_write_fails(db, host):
    """If a host write fails after step 3, the prior bearer must
    still be active so the host keeps working until the next
    successful apply."""
    from app.db.models import HostMirrorServeCredential
    from app.services.mirror_serve_credential_service import (
        MirrorServeCredentialService,
    )

    mirror = _make_mirror(db)
    _add_signing_key(db, mirror, fpr="A" * 40)
    _bind_profile_to_host(db, host, mirror)

    cred_svc = MirrorServeCredentialService(db)
    prior = cred_svc.issue(host_id=host.id, mirror_id=mirror.id)
    prior_id = prior.credential_id

    # Same fail-on-write call sequence as the existing
    # test_apply_bails_on_write_failure: trust install (3) +
    # ensure_parent_dir x2 (deb) + ls x2 + write fail + cleanup rm.
    success = MagicMock(exit_code=0, stderr=b"", stdout=b"")
    fail = MagicMock(exit_code=1, stderr=b"disk full", stdout=b"")
    transport = _fake_transport(
        run_outcomes=[
            success,  # install -d (trust)
            success,  # install tmp (trust)
            success,  # mv (trust)
            success,  # ensure_parent_dir /etc/apt/sources.list.d
            success,  # ensure_parent_dir /etc/apt/auth.conf.d
            fail,  # write managed file step 1 fails
            success,  # orphan rm cleanup
        ],
        list_outputs=[
            MagicMock(exit_code=0, stderr=b"", stdout=b""),
            MagicMock(exit_code=0, stderr=b"", stdout=b""),
        ],
    )
    outcome = await apply_content_profile_to_host(
        db, host, transport, serve_base_url="https://x.com"
    )
    assert outcome.state == "failed"

    # Prior credential is STILL active — host keeps working.
    prior_row = (
        db.query(HostMirrorServeCredential)
        .filter(HostMirrorServeCredential.id == prior_id)
        .one()
    )
    assert prior_row.revoked_at is None


@pytest.mark.asyncio
async def test_apply_pending_cutover_triggers_trust_reinstall(db, host):
    """A host that has the active fingerprint installed but is missing
    a pending_cutover key must re-run the trust install primitive so
    the next rotation cutover doesn't strand it."""
    from app.db.models import HostMirrorTrust, MirrorSigningKey
    from app.services.mirror_signing_key_service import vault_path_for

    active_fp = "A" * 40
    pending_fp = "B" * 40
    mirror = _make_mirror(db)
    _add_signing_key(db, mirror, fpr=active_fp)
    # Add a pending_cutover key
    db.add(
        MirrorSigningKey(
            mirror_repo_id=mirror.id,
            status="pending_cutover",
            gpg_fingerprint=pending_fp,
            key_uid=f"Praxis Mirror {mirror.slug} pending",
            vault_path=vault_path_for(mirror.slug, pending_fp),
            armored_public_key="-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-PEND\n-----END-----\n",
        )
    )
    db.commit()

    _bind_profile_to_host(db, host, mirror)

    # Host has only the active fingerprint installed — pending is
    # missing.
    db.add(
        HostMirrorTrust(
            host_id=host.id,
            mirror_id=mirror.id,
            installed_fingerprints=[active_fp],
            last_installed_at=datetime.utcnow(),
        )
    )
    db.commit()

    transport = _fake_transport(
        list_outputs=[
            MagicMock(exit_code=0, stderr=b"", stdout=b""),
            MagicMock(exit_code=0, stderr=b"", stdout=b""),
        ]
    )
    outcome = await apply_content_profile_to_host(
        db, host, transport, serve_base_url="https://x.com"
    )
    assert outcome.state == "applied"
    # Trust install ran because pending_cutover wasn't installed.
    assert outcome.trust_installed_for_mirrors == [mirror.slug]


@pytest.mark.asyncio
async def test_apply_rpm_excludes_rotating_out_from_gpgkey(db, host):
    """rpm rendering must only reference fingerprints the host is
    GUARANTEED to have installed — active + pending_cutover. A
    rotating_out key is allowed to be missing on the host
    (per _needs_trust_install), so emitting it as gpgkey would
    point at a file that may not exist.
    """
    from app.db.models import (
        ContentChannel,
        ContentChannelRepo,
        ContentProfile,
        ContentProfileChannel,
        HostContentProfileSubscription,
        MirrorRepo,
        MirrorSigningKey,
    )
    from app.services.mirror_signing_key_service import vault_path_for

    rpm_mirror = MirrorRepo(
        slug="apply-rpm-mirror",
        display_name="rpm",
        package_family="rpm",
        upstream_url="http://x/y",
        distribution="9",
        components="[]",
        architectures='["x86_64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(rpm_mirror)
    db.flush()
    active_fp = "A" * 40
    rotating_fp = "C" * 40
    for status, fpr in (("active", active_fp), ("rotating_out", rotating_fp)):
        db.add(
            MirrorSigningKey(
                mirror_repo_id=rpm_mirror.id,
                status=status,
                gpg_fingerprint=fpr,
                key_uid=f"Praxis Mirror {rpm_mirror.slug} {status}",
                vault_path=vault_path_for(rpm_mirror.slug, fpr),
                armored_public_key=(
                    f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-{fpr[:4]}\n-----END-----\n"
                ),
            )
        )
    db.commit()

    channel = ContentChannel(slug="rpm-c", display_name="rpm", package_family="rpm")
    db.add(channel)
    db.flush()
    db.add(ContentChannelRepo(channel_id=channel.id, mirror_id=rpm_mirror.id))
    profile = ContentProfile(slug="rpm-prof", display_name="rpm", package_family="rpm")
    db.add(profile)
    db.flush()
    db.add(ContentProfileChannel(profile_id=profile.id, channel_id=channel.id))
    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=profile.id))
    db.commit()

    transport = _fake_transport(
        list_outputs=[MagicMock(exit_code=0, stderr=b"", stdout=b"")]
    )
    outcome = await apply_content_profile_to_host(
        db, host, transport, serve_base_url="https://x.com"
    )
    assert outcome.state == "applied", outcome.error_text
    # Find the install argv that wrote the .repo and inspect the body.
    write_call = next(
        c
        for c in transport._calls
        if "/etc/yum.repos.d/praxis-profile-rpm-prof.repo.praxis-tmp" in c["argv"]
    )
    body = write_call["stdin"].decode("utf-8")
    # active fp8 (lowercase) is referenced; rotating fp8 is NOT.
    assert active_fp[:8].lower() in body
    assert rotating_fp[:8].lower() not in body


@pytest.mark.asyncio
async def test_apply_empty_resolved_profile_removes_obsolete_no_writes(db, host):
    """A resolved profile with zero entries (no channels, or all
    soft-deleted) is legal — apply removes obsolete praxis-profile-*
    files but writes none."""
    from app.db.models import ContentProfile, HostContentProfileSubscription

    # Create a profile with no channels.
    profile = ContentProfile(
        slug="empty-prof", display_name="Empty", package_family="deb"
    )
    db.add(profile)
    db.flush()
    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=profile.id))
    db.commit()

    obsolete = "/etc/apt/sources.list.d/praxis-profile-stage.list"
    transport = _fake_transport(
        list_outputs=[
            MagicMock(
                exit_code=0,
                stderr=b"",
                stdout=(obsolete + "\n").encode("utf-8"),
            ),
            MagicMock(exit_code=0, stderr=b"", stdout=b""),
        ]
    )
    outcome = await apply_content_profile_to_host(
        db, host, transport, serve_base_url="https://x.com"
    )
    assert outcome.state == "applied"
    assert outcome.written_paths == []
    assert obsolete in outcome.removed_paths


@pytest.mark.asyncio
async def test_apply_bails_on_write_failure(db, host):
    mirror = _make_mirror(db)
    _add_signing_key(db, mirror, fpr="A" * 40)
    _bind_profile_to_host(db, host, mirror)

    # Walk the call sequence:
    # 1. trust install: install -d + install (tmp) + mv = 3 successes
    # 2. ls /etc/apt/sources.list.d (sh -c) — empty
    # 3. ls /etc/apt/auth.conf.d (sh -c) — empty
    # 4. write .list step 1 (install /dev/stdin tmp) — FAIL
    # 5. orphan rm cleanup
    success = MagicMock(exit_code=0, stderr=b"", stdout=b"")
    fail = MagicMock(exit_code=1, stderr=b"disk full", stdout=b"")
    transport = _fake_transport(
        run_outcomes=[
            success,  # install -d
            success,  # install tmp
            success,  # mv (trust install complete)
            fail,  # write managed file step 1 fails
            success,  # orphan cleanup rm
        ],
        list_outputs=[
            MagicMock(exit_code=0, stderr=b"", stdout=b""),
            MagicMock(exit_code=0, stderr=b"", stdout=b""),
        ],
    )

    outcome = await apply_content_profile_to_host(
        db, host, transport, serve_base_url="https://x.com"
    )
    assert outcome.state == "failed"
    assert "disk full" in outcome.error_text
    # Earlier successes are reflected in the partial state for
    # operator triage: trust + cred ran, no files written.
    assert outcome.trust_installed_for_mirrors == [mirror.slug]
    assert outcome.credentials_issued_for_mirrors == [mirror.slug]
    assert outcome.written_paths == []
