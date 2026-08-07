"""PRA-158 #3c: install_mirror_trust_on_host service tests.

Transport is a MagicMock that captures calls so the install primitive
runs end-to-end against a fake remote. Real SSH/agent integration is
covered by PRA-153's transport tests; this file asserts the install
shape (paths, modes, host_mirror_trust upsert) and the package-family
branching.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.db.models import (
    Credential,
    Group,
    HostMirrorTrust,
    MirrorRepo,
    MirrorSigningKey,
    System,
)
from app.services.mirror_host_trust import install_mirror_trust_on_host
from app.services.mirror_signing_key_service import vault_path_for

_ACTIVE_FPR = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
_PENDING_FPR = "B" * 40


def _add_key(db, mirror, *, status, fpr):
    armored = f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-{fpr}\n-----END-----\n"
    row = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status=status,
        gpg_fingerprint=fpr,
        key_uid=f"Praxis Mirror Signing {mirror.slug} {fpr}",
        vault_path=vault_path_for(mirror.slug, fpr),
        armored_public_key=armored,
    )
    db.add(row)
    db.commit()
    return row


def _make_host(db, seed_distro, hostname: str = "test-trust-host") -> System:
    """System construction needs Credential + Group + Distro per the
    PRA-154 ``_make_system`` pattern.
    """
    grp = Group(name=f"trust-grp-{hostname}", description="trust test")
    db.add(grp)
    db.flush()
    cred = Credential(
        name=f"trust-cred-{hostname}", auth_method="ssh_key", username="root"
    )
    db.add(cred)
    db.flush()
    h = System(
        hostname=hostname,
        ip_address="10.0.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=grp.id,
        credentials_id=cred.id,
    )
    db.add(h)
    db.commit()
    db.refresh(h)
    return h


@pytest.fixture
def host(db, seed_distro) -> System:
    return _make_host(db, seed_distro)


@pytest.fixture
def deb_mirror(db) -> MirrorRepo:
    m = MirrorRepo(
        slug="ubuntu-jammy",
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
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


@pytest.fixture
def rpm_mirror(db) -> MirrorRepo:
    m = MirrorRepo(
        slug="rocky-9",
        display_name="Rocky 9",
        package_family="rpm",
        upstream_url="http://dl.rockylinux.org/pub/rocky/9",
        distribution="9",
        components="[]",
        architectures='["x86_64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


def _make_transport(name: str = "ssh"):
    """Return a MagicMock transport with an async ``run_command``.

    Captures every call (argv + stdin) so tests can assert the
    sudo-install argv shape and the stdin body bytes. ``name``
    controls the ``transport.name`` attribute that the install
    primitive uses to decide whether to prefix with ``sudo`` (ssh)
    or run direct (agent runs as root per PRA-153 lock).
    """
    t = MagicMock()
    t.name = name
    run_calls: list = []

    async def _run(argv, *, stdin=None, timeout_seconds=None):
        run_calls.append({"argv": list(argv), "stdin": stdin})
        return MagicMock(exit_code=0, stderr=b"", stdout=b"")

    t.run_command = _run
    t._run_calls = run_calls
    return t


# ---------------------------------------------------------------------------
# deb branch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deb_install_uses_sudo_install_pattern_on_ssh(db, deb_mirror, host):
    """Locked sequence (#3-d/#3-e): SSH transport prefixes every
    privileged command with ``sudo -n`` (noninteractive — fails fast
    on password-required sudoers, never hangs / eats stdin), then:

      1. ``install -d ...`` for the parent dir.
      2. ``install -m 0644 -o root -g root /dev/stdin <FINAL>.praxis-tmp``
         — body via stdin to a same-directory tmp.
      3. ``mv -f <FINAL>.praxis-tmp <FINAL>`` — atomic rename swap.

    Step 2's tmp-then-rename preserves last-good FINAL on a mid-write
    or disk-full failure (``install`` is NOT a contractual atomic
    temp+rename for updating an existing file).
    """
    _add_key(db, deb_mirror, status="active", fpr=_ACTIVE_FPR)
    _add_key(db, deb_mirror, status="pending_cutover", fpr=_PENDING_FPR)

    transport = _make_transport(name="ssh")
    result = await install_mirror_trust_on_host(db, deb_mirror, host, transport)

    assert result.ok, result.error_text
    assert result.installed_fingerprints == [_ACTIVE_FPR, _PENDING_FPR]
    final_path = "/etc/apt/keyrings/praxis-mirror-ubuntu-jammy.asc"
    tmp_path = f"{final_path}.praxis-tmp"
    assert result.written_paths == [final_path]

    cmds = transport._run_calls
    # 1 install -d + 1 install (tmp) + 1 mv = 3.
    assert len(cmds) == 3

    # install -d, sudo -n prefixed.
    assert cmds[0]["argv"] == [
        "sudo",
        "-n",
        "install",
        "-d",
        "-m",
        "0755",
        "-o",
        "root",
        "-g",
        "root",
        "/etc/apt/keyrings",
    ]
    assert cmds[0]["stdin"] is None

    # install body to .praxis-tmp; FINAL is NOT in argv.
    assert cmds[1]["argv"] == [
        "sudo",
        "-n",
        "install",
        "-m",
        "0644",
        "-o",
        "root",
        "-g",
        "root",
        "/dev/stdin",
        tmp_path,
    ]
    assert final_path not in cmds[1]["argv"]
    body = cmds[1]["stdin"].decode("utf-8")
    assert _ACTIVE_FPR in body
    assert _PENDING_FPR in body
    assert body.count("BEGIN PGP PUBLIC KEY BLOCK") == 2

    # mv -f tmp -> final, sudo -n prefixed.
    assert cmds[2]["argv"] == ["sudo", "-n", "mv", "-f", tmp_path, final_path]
    assert cmds[2]["stdin"] is None


@pytest.mark.asyncio
async def test_deb_install_skips_sudo_on_agent_transport(db, deb_mirror, host):
    """Agent transport runs as root per the PRA-153 lock; sudo prefix
    is unnecessary and would require sudo on the agent path which
    isn't part of v1.
    """
    _add_key(db, deb_mirror, status="active", fpr=_ACTIVE_FPR)
    transport = _make_transport(name="agent")

    result = await install_mirror_trust_on_host(db, deb_mirror, host, transport)
    assert result.ok, result.error_text

    cmds = transport._run_calls
    # No sudo prefix anywhere; install + mv only.
    for c in cmds:
        assert c["argv"][0] != "sudo", f"agent path should not use sudo: {c['argv']!r}"
        assert c["argv"][0] in {"install", "mv"}


@pytest.mark.asyncio
async def test_deb_install_upserts_host_mirror_trust(db, deb_mirror, host):
    _add_key(db, deb_mirror, status="active", fpr=_ACTIVE_FPR)
    transport = _make_transport()
    await install_mirror_trust_on_host(db, deb_mirror, host, transport)

    row = (
        db.query(HostMirrorTrust)
        .filter_by(host_id=host.id, mirror_id=deb_mirror.id)
        .one()
    )
    assert row.installed_fingerprints == [_ACTIVE_FPR]
    assert isinstance(row.last_installed_at, datetime)


@pytest.mark.asyncio
async def test_deb_install_idempotent_overwrite(db, deb_mirror, host):
    _add_key(db, deb_mirror, status="active", fpr=_ACTIVE_FPR)
    transport = _make_transport()
    await install_mirror_trust_on_host(db, deb_mirror, host, transport)
    first_at = (
        db.query(HostMirrorTrust)
        .filter_by(host_id=host.id, mirror_id=deb_mirror.id)
        .one()
        .last_installed_at
    )

    # Second install — same key set, single existing row updated.
    await install_mirror_trust_on_host(db, deb_mirror, host, transport)
    rows = (
        db.query(HostMirrorTrust)
        .filter_by(host_id=host.id, mirror_id=deb_mirror.id)
        .all()
    )
    assert len(rows) == 1
    assert rows[0].last_installed_at >= first_at


# ---------------------------------------------------------------------------
# rpm branch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rpm_install_writes_one_file_per_fingerprint(db, rpm_mirror, host):
    _add_key(db, rpm_mirror, status="active", fpr=_ACTIVE_FPR)
    _add_key(db, rpm_mirror, status="pending_cutover", fpr=_PENDING_FPR)

    transport = _make_transport(name="ssh")
    result = await install_mirror_trust_on_host(db, rpm_mirror, host, transport)

    assert result.ok, result.error_text
    assert sorted(result.installed_fingerprints) == sorted([_ACTIVE_FPR, _PENDING_FPR])

    fp8_active = _ACTIVE_FPR[:8].lower()
    fp8_pending = _PENDING_FPR[:8].lower()
    final_active = f"/etc/pki/rpm-gpg/RPM-GPG-KEY-PRAXIS-MIRROR-rocky-9-{fp8_active}"
    final_pending = f"/etc/pki/rpm-gpg/RPM-GPG-KEY-PRAXIS-MIRROR-rocky-9-{fp8_pending}"

    cmds = transport._run_calls
    # 1 install -d + 2*(install-tmp + mv) = 5 commands.
    assert len(cmds) == 5
    assert cmds[0]["argv"][:4] == ["sudo", "-n", "install", "-d"]
    assert cmds[0]["argv"][-1] == "/etc/pki/rpm-gpg"

    install_calls = [c for c in cmds[1:] if "install" in c["argv"]]
    mv_calls = [c for c in cmds[1:] if "mv" in c["argv"]]
    assert len(install_calls) == 2
    assert len(mv_calls) == 2

    # Every install writes to a .praxis-tmp; final paths only appear
    # as the destination of mv -f.
    install_targets = sorted(c["argv"][-1] for c in install_calls)
    assert install_targets == sorted(
        [f"{final_active}.praxis-tmp", f"{final_pending}.praxis-tmp"]
    )
    for c in install_calls:
        assert c["argv"][:3] == ["sudo", "-n", "install"]
        assert c["argv"][-2] == "/dev/stdin"
        body = c["stdin"].decode("utf-8")
        if c["argv"][-1] == f"{final_active}.praxis-tmp":
            assert _ACTIVE_FPR in body
        else:
            assert _PENDING_FPR in body

    mv_dests = sorted(c["argv"][-1] for c in mv_calls)
    assert mv_dests == sorted([final_active, final_pending])
    for c in mv_calls:
        assert c["argv"][:4] == ["sudo", "-n", "mv", "-f"]


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_keys_returns_failure(db, deb_mirror, host):
    """Bootstrap not yet run — install must surface this clearly,
    not silently write an empty bundle.
    """
    transport = _make_transport()
    result = await install_mirror_trust_on_host(db, deb_mirror, host, transport)
    assert result.ok is False
    assert "no signing keys" in (result.error_text or "")
    # No remote command attempted.
    assert transport._run_calls == []


@pytest.mark.asyncio
async def test_install_d_failure_aborts_install(db, deb_mirror, host):
    """``install -d`` rc!=0 (e.g. EPERM under non-root + no sudoers) →
    HostInstallResult(ok=False), no host_mirror_trust upsert.
    """
    _add_key(db, deb_mirror, status="active", fpr=_ACTIVE_FPR)
    transport = _make_transport(name="ssh")

    async def _run(argv, *, stdin=None, timeout_seconds=None):
        transport._run_calls.append({"argv": list(argv), "stdin": stdin})
        if "install" in argv and "-d" in argv:
            return MagicMock(exit_code=1, stderr=b"permission denied", stdout=b"")
        return MagicMock(exit_code=0, stderr=b"", stdout=b"")

    transport.run_command = _run

    result = await install_mirror_trust_on_host(db, deb_mirror, host, transport)
    assert result.ok is False
    assert "install -d" in (result.error_text or "")
    assert "permission denied" in (result.error_text or "")
    assert (
        db.query(HostMirrorTrust)
        .filter_by(host_id=host.id, mirror_id=deb_mirror.id)
        .one_or_none()
        is None
    )


@pytest.mark.asyncio
async def test_install_d_transport_exception_returns_per_host_failure(
    db, deb_mirror, host
):
    """The ``run_command`` call can raise (TransportError, socket
    failure, broker hiccup). The service must convert that into a
    HostInstallResult, not let it bubble out and produce a 500 at the
    route level.
    """
    _add_key(db, deb_mirror, status="active", fpr=_ACTIVE_FPR)
    transport = _make_transport(name="ssh")

    async def _raising_run(argv, *, stdin=None, timeout_seconds=None):
        raise RuntimeError("simulated transport collapse")

    transport.run_command = _raising_run

    result = await install_mirror_trust_on_host(db, deb_mirror, host, transport)
    assert result.ok is False
    assert "install -d" in (result.error_text or "")
    assert "transport:" in (result.error_text or "")
    assert "simulated transport collapse" in (result.error_text or "")
    assert (
        db.query(HostMirrorTrust)
        .filter_by(host_id=host.id, mirror_id=deb_mirror.id)
        .one_or_none()
        is None
    )


@pytest.mark.asyncio
async def test_install_tmp_failure_preserves_final_and_cleans_orphan(
    db, deb_mirror, host
):
    """A failed ``install`` to the .praxis-tmp must
    NOT touch the final path (last-good preserved) and must trigger a
    best-effort ``rm -f`` of the orphan tmp so a future install isn't
    tripped up by stale state.
    """
    _add_key(db, deb_mirror, status="active", fpr=_ACTIVE_FPR)
    transport = _make_transport(name="ssh")

    async def _run(argv, *, stdin=None, timeout_seconds=None):
        transport._run_calls.append({"argv": list(argv), "stdin": stdin})
        # Fail the install-to-tmp step (it has /dev/stdin in argv).
        if "/dev/stdin" in argv:
            return MagicMock(exit_code=1, stderr=b"no space left on device", stdout=b"")
        return MagicMock(exit_code=0, stderr=b"", stdout=b"")

    transport.run_command = _run

    result = await install_mirror_trust_on_host(db, deb_mirror, host, transport)
    assert result.ok is False
    assert "install" in (result.error_text or "")
    assert ".praxis-tmp" in (result.error_text or "")
    assert "no space left on device" in (result.error_text or "")

    # No mv attempted (final path never targeted).
    assert not any(
        "mv" in c["argv"] and c["argv"][-1].endswith(".asc")
        for c in transport._run_calls
    )
    # Orphan cleanup was attempted.
    assert any(
        c["argv"][:3] == ["sudo", "-n", "rm"] and ".praxis-tmp" in c["argv"][-1]
        for c in transport._run_calls
    ), f"expected sudo -n rm -f *.praxis-tmp cleanup, got {transport._run_calls!r}"
    # No host_mirror_trust upsert.
    assert (
        db.query(HostMirrorTrust)
        .filter_by(host_id=host.id, mirror_id=deb_mirror.id)
        .one_or_none()
        is None
    )


@pytest.mark.asyncio
async def test_install_tmp_transport_exception_returns_per_host_failure(
    db, deb_mirror, host
):
    """Transport-exception protection on the install-to-tmp step."""
    _add_key(db, deb_mirror, status="active", fpr=_ACTIVE_FPR)
    transport = _make_transport(name="ssh")

    async def _run(argv, *, stdin=None, timeout_seconds=None):
        transport._run_calls.append({"argv": list(argv), "stdin": stdin})
        if "/dev/stdin" in argv:
            raise RuntimeError("simulated transport collapse during install")
        return MagicMock(exit_code=0, stderr=b"", stdout=b"")

    transport.run_command = _run

    result = await install_mirror_trust_on_host(db, deb_mirror, host, transport)
    assert result.ok is False
    assert "install" in (result.error_text or "")
    assert "transport:" in (result.error_text or "")
    assert "simulated transport collapse" in (result.error_text or "")
    assert (
        db.query(HostMirrorTrust)
        .filter_by(host_id=host.id, mirror_id=deb_mirror.id)
        .one_or_none()
        is None
    )


@pytest.mark.asyncio
async def test_mv_failure_preserves_final_at_last_good(db, deb_mirror, host):
    """If the atomic ``mv -f`` fails, the final path
    is still at last-good (rename didn't happen) and host_mirror_trust
    is NOT upserted so slice #5's cutover-gate sees the right state.
    """
    _add_key(db, deb_mirror, status="active", fpr=_ACTIVE_FPR)
    transport = _make_transport(name="ssh")

    async def _run(argv, *, stdin=None, timeout_seconds=None):
        transport._run_calls.append({"argv": list(argv), "stdin": stdin})
        if "mv" in argv:
            return MagicMock(
                exit_code=1,
                stderr=b"cross-device link",
                stdout=b"",
            )
        return MagicMock(exit_code=0, stderr=b"", stdout=b"")

    transport.run_command = _run

    result = await install_mirror_trust_on_host(db, deb_mirror, host, transport)
    assert result.ok is False
    assert "mv" in (result.error_text or "")
    assert "cross-device link" in (result.error_text or "")
    assert (
        db.query(HostMirrorTrust)
        .filter_by(host_id=host.id, mirror_id=deb_mirror.id)
        .one_or_none()
        is None
    )


@pytest.mark.asyncio
async def test_sudo_n_fails_fast_on_password_required(db, deb_mirror, host):
    """``sudo -n`` (noninteractive) means
    password-required sudoers fail fast with a clear stderr instead of
    hanging or eating /dev/stdin. We model this as the install-to-tmp
    step returning rc!=0 with the canonical sudo error message.
    """
    _add_key(db, deb_mirror, status="active", fpr=_ACTIVE_FPR)
    transport = _make_transport(name="ssh")

    async def _run(argv, *, stdin=None, timeout_seconds=None):
        transport._run_calls.append({"argv": list(argv), "stdin": stdin})
        # sudo -n returns rc=1 with this stderr when sudoers requires
        # a password — this is the path operators on password-sudo
        # hosts hit, by design.
        if argv[:2] == ["sudo", "-n"]:
            return MagicMock(
                exit_code=1,
                stderr=b"sudo: a password is required",
                stdout=b"",
            )
        return MagicMock(exit_code=0, stderr=b"", stdout=b"")

    transport.run_command = _run

    result = await install_mirror_trust_on_host(db, deb_mirror, host, transport)
    assert result.ok is False
    assert "password is required" in (result.error_text or "")
    # Failed at install-d (the very first sudo -n call), no /dev/stdin
    # write attempted.
    install_d_calls = [
        c for c in transport._run_calls if "install" in c["argv"] and "-d" in c["argv"]
    ]
    assert len(install_d_calls) == 1
    stdin_calls = [c for c in transport._run_calls if "/dev/stdin" in c["argv"]]
    assert stdin_calls == []


@pytest.mark.asyncio
async def test_unknown_package_family_rejected(db, deb_mirror, host):
    """Defensive: unknown family returns a clear error rather than
    a NotImplementedError surfacing to the caller. The DB CHECK
    constraint blocks real inserts of unknown families, so this test
    uses a stand-in object that proxies the real row's id/slug with
    a mutated package_family — keeps the persistent row clean.
    """
    _add_key(db, deb_mirror, status="active", fpr=_ACTIVE_FPR)

    class _StandIn:
        id = deb_mirror.id
        slug = deb_mirror.slug
        package_family = "snap"  # not deb/rpm

    transport = _make_transport()
    result = await install_mirror_trust_on_host(db, _StandIn(), host, transport)
    assert result.ok is False
    assert "unsupported package_family" in (result.error_text or "")
