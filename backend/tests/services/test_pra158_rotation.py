"""PRA-158 #5a: rotation primitives in MirrorSigningKeyService.

Covers rotate_prepare, cutover_preview, cutover (gated + force),
retire, and auto_retire_expired. GPG subprocess is monkeypatched so
unit tests run instantly without needing the real binary; the real-
gpg integration coverage lives in slice #1's GPG primitive tests.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from app.db.models import (
    Credential,
    Group,
    HostMirrorTrust,
    MirrorRepo,
    MirrorSigningKey,
    System,
)
from app.services import mirror_signing_key_service as svc_module
from app.services.mirror_signing_key_service import (
    CutoverBlocked,
    MirrorSigningKeyService,
    RotationError,
    RotationNotFound,
    vault_path_for,
)
from tests.conftest import unique_test_ip

_ACTIVE_FPR = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
_PENDING_FPR = "B" * 40
_OLD_FPR = "C" * 40


@pytest.fixture
def patch_gpg(monkeypatch):
    """Stub gpg gen+export. Each call to ``generate_keypair`` returns
    a different fingerprint so tests that prepare-after-bootstrap see
    distinct active vs pending fingerprints.
    """
    fingerprints = iter([_ACTIVE_FPR, _PENDING_FPR, _OLD_FPR, "D" * 40, "E" * 40])

    def fake_generate(home, slug):
        return next(fingerprints)

    def fake_export_secret(home, fpr):
        return f"-----BEGIN PGP PRIVATE KEY BLOCK-----\nFAKE-{fpr}\n-----END-----\n"

    def fake_export_public(home, fpr):
        return f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-{fpr}\n-----END-----\n"

    monkeypatch.setattr(svc_module.mirror_gpg, "generate_keypair", fake_generate)
    monkeypatch.setattr(
        svc_module.mirror_gpg, "export_secret_armored", fake_export_secret
    )
    monkeypatch.setattr(
        svc_module.mirror_gpg, "export_public_armored", fake_export_public
    )


@pytest.fixture
def mirror(db) -> MirrorRepo:
    m = MirrorRepo(
        slug="rotation-test",
        display_name="Rotation Test",
        package_family="deb",
        upstream_url="http://example.com/ubuntu",
        distribution="jammy",
        components='["main"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        verify_upstream_signature=False,
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


def _make_host(db, seed_distro, hostname: str) -> System:
    grp = Group(name=f"rot-grp-{hostname}", description="rotation test")
    db.add(grp)
    db.flush()
    cred = Credential(
        name=f"rot-cred-{hostname}", auth_method="ssh_key", username="root"
    )
    db.add(cred)
    db.flush()
    h = System(
        hostname=hostname,
        ip_address=unique_test_ip(),
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


# ---------------------------------------------------------------------------
# rotate_prepare
# ---------------------------------------------------------------------------


def test_rotate_prepare_creates_pending_alongside_active(
    db, mock_vault, patch_gpg, mirror
):
    service = MirrorSigningKeyService(db)
    active = service.ensure_active(mirror)
    assert active.status == "active"
    assert active.gpg_fingerprint == _ACTIVE_FPR

    pending = service.rotate_prepare(mirror)
    assert pending.status == "pending_cutover"
    assert pending.gpg_fingerprint == _PENDING_FPR
    assert pending.armored_public_key is not None

    # Active is unchanged — signing still uses it until cutover.
    db.refresh(active)
    assert active.status == "active"


def test_rotate_prepare_refuses_when_already_pending(db, mock_vault, patch_gpg, mirror):
    service = MirrorSigningKeyService(db)
    service.ensure_active(mirror)
    service.rotate_prepare(mirror)

    with pytest.raises(RotationError, match="already has a pending_cutover key"):
        service.rotate_prepare(mirror)


def test_rotate_prepare_works_without_active(db, mock_vault, patch_gpg, mirror):
    """Edge case: prepare runs before bootstrap. The DB constraint
    only forbids two pending_cutover, not pending without active.
    """
    service = MirrorSigningKeyService(db)
    pending = service.rotate_prepare(mirror)
    assert pending.status == "pending_cutover"


# ---------------------------------------------------------------------------
# cutover_preview
# ---------------------------------------------------------------------------


def test_cutover_preview_raises_without_pending(db, mock_vault, patch_gpg, mirror):
    service = MirrorSigningKeyService(db)
    service.ensure_active(mirror)
    with pytest.raises(RotationError, match="no pending_cutover"):
        service.cutover_preview(mirror.id)


def test_cutover_preview_empty_when_no_hosts(db, mock_vault, patch_gpg, mirror):
    service = MirrorSigningKeyService(db)
    service.ensure_active(mirror)
    service.rotate_prepare(mirror)

    preview = service.cutover_preview(mirror.id)
    assert preview["pending_fingerprint"] == _PENDING_FPR
    assert preview["hosts_missing_pending"] == []
    assert preview["hosts_never_installed"] == []
    assert preview["hosts_stale_trust_record"] == []


def test_cutover_preview_flags_hosts_missing_pending(
    db, mock_vault, patch_gpg, mirror, seed_distro
):
    service = MirrorSigningKeyService(db)
    service.ensure_active(mirror)
    service.rotate_prepare(mirror)

    h_ready = _make_host(db, seed_distro, "ready.example.com")
    h_lagging = _make_host(db, seed_distro, "lagging.example.com")

    db.add_all(
        [
            HostMirrorTrust(
                host_id=h_ready.id,
                mirror_id=mirror.id,
                installed_fingerprints=[_ACTIVE_FPR, _PENDING_FPR],
            ),
            HostMirrorTrust(
                host_id=h_lagging.id,
                mirror_id=mirror.id,
                installed_fingerprints=[_ACTIVE_FPR],  # missing pending
            ),
        ]
    )
    db.commit()

    preview = service.cutover_preview(mirror.id)
    assert preview["hosts_missing_pending"] == [h_lagging.id]
    assert h_ready.id not in preview["hosts_missing_pending"]


# ---------------------------------------------------------------------------
# cutover — gated + force
# ---------------------------------------------------------------------------


def test_cutover_promotes_pending_when_all_hosts_ready(
    db, mock_vault, patch_gpg, mirror, seed_distro
):
    service = MirrorSigningKeyService(db)
    active = service.ensure_active(mirror)
    pending = service.rotate_prepare(mirror)
    assert active.gpg_fingerprint == _ACTIVE_FPR
    assert pending.gpg_fingerprint == _PENDING_FPR

    h = _make_host(db, seed_distro, "ready.example.com")
    db.add(
        HostMirrorTrust(
            host_id=h.id,
            mirror_id=mirror.id,
            installed_fingerprints=[_ACTIVE_FPR, _PENDING_FPR],
        )
    )
    db.commit()

    new_active = service.cutover(mirror)

    assert new_active.id == pending.id
    assert new_active.status == "active"
    assert new_active.cutover_at is None

    db.refresh(active)
    assert active.status == "rotating_out"
    assert active.cutover_at is not None


def test_cutover_blocked_when_host_lacks_pending(
    db, mock_vault, patch_gpg, mirror, seed_distro
):
    service = MirrorSigningKeyService(db)
    service.ensure_active(mirror)
    service.rotate_prepare(mirror)

    h = _make_host(db, seed_distro, "lagging.example.com")
    db.add(
        HostMirrorTrust(
            host_id=h.id,
            mirror_id=mirror.id,
            installed_fingerprints=[_ACTIVE_FPR],
        )
    )
    db.commit()

    with pytest.raises(CutoverBlocked) as excinfo:
        service.cutover(mirror)
    assert excinfo.value.preview["hosts_missing_pending"] == [h.id]
    assert excinfo.value.preview["pending_fingerprint"] == _PENDING_FPR

    # State machine unchanged.
    active_now = service.get_active(mirror.id)
    assert active_now.gpg_fingerprint == _ACTIVE_FPR
    pending_now = service.get_pending_cutover(mirror.id)
    assert pending_now.gpg_fingerprint == _PENDING_FPR


def test_cutover_force_overrides_gate_and_emits_audit(
    db, mock_vault, patch_gpg, mirror, seed_distro
):
    service = MirrorSigningKeyService(db)
    service.ensure_active(mirror)
    service.rotate_prepare(mirror)

    h = _make_host(db, seed_distro, "lagging-forced.example.com")
    db.add(
        HostMirrorTrust(
            host_id=h.id,
            mirror_id=mirror.id,
            installed_fingerprints=[_ACTIVE_FPR],
        )
    )
    db.commit()

    with patch("app.services.audit_event_service.safe_emit") as mock_audit:
        new_active = service.cutover(mirror, force=True, actor_user_id=42)

    assert new_active.gpg_fingerprint == _PENDING_FPR
    assert new_active.status == "active"
    # Audit captured the force-override with structured counts.
    # Emission happens AFTER state-transition commit,
    # on a fresh session — no ``db=`` kwarg passed to safe_emit.
    mock_audit.assert_called_once()
    kwargs = mock_audit.call_args.kwargs
    assert "db" not in kwargs
    assert kwargs["action"] == "mirror.signing_key.cutover.forced"
    assert kwargs["actor_user_id"] == 42
    assert kwargs["target_kind"] == "mirror"
    assert kwargs["target_id"] == str(mirror.id)
    ctx = kwargs["context"]
    assert ctx["pending_fingerprint"] == _PENDING_FPR
    assert ctx["previous_active_fingerprint"] == _ACTIVE_FPR
    assert ctx["hosts_missing_pending_count"] == 1
    assert ctx["hosts_never_installed_count"] == 0


def test_cutover_force_emits_audit_only_after_state_transition_commit(
    db, mock_vault, patch_gpg, mirror, seed_distro
):
    """A forced cutover audit row must NEVER describe
    an override that didn't actually commit. Emission happens after
    the state-transition commit — when safe_emit fires, get_active
    must already see the new active key.
    """
    service = MirrorSigningKeyService(db)
    service.ensure_active(mirror)
    service.rotate_prepare(mirror)

    h = _make_host(db, seed_distro, "lagging-order.example.com")
    db.add(
        HostMirrorTrust(
            host_id=h.id,
            mirror_id=mirror.id,
            installed_fingerprints=[_ACTIVE_FPR],
        )
    )
    db.commit()

    observed_state_at_emit = {}

    def _capture(**kwargs):
        # By the time safe_emit is called, the rotation commit must
        # have landed. Probe the DB on the same session to confirm.
        active_now = service.get_active(mirror.id)
        observed_state_at_emit["new_active_fpr"] = (
            active_now.gpg_fingerprint if active_now else None
        )
        pending_now = service.get_pending_cutover(mirror.id)
        observed_state_at_emit["still_pending"] = pending_now is not None

    with patch(
        "app.services.audit_event_service.safe_emit",
        side_effect=_capture,
    ):
        service.cutover(mirror, force=True, actor_user_id=7)

    assert observed_state_at_emit["new_active_fpr"] == _PENDING_FPR
    assert observed_state_at_emit["still_pending"] is False


def test_cutover_force_without_blocked_hosts_does_not_emit_audit(
    db, mock_vault, patch_gpg, mirror
):
    """force=True with no blocked hosts is a no-op for audit — nothing
    was actually overridden.
    """
    service = MirrorSigningKeyService(db)
    service.ensure_active(mirror)
    service.rotate_prepare(mirror)

    with patch("app.services.audit_event_service.safe_emit") as mock_audit:
        service.cutover(mirror, force=True, actor_user_id=42)

    mock_audit.assert_not_called()


def test_cutover_raises_when_no_pending(db, mock_vault, patch_gpg, mirror):
    service = MirrorSigningKeyService(db)
    service.ensure_active(mirror)
    with pytest.raises(RotationError, match="no pending_cutover"):
        service.cutover(mirror)


# ---------------------------------------------------------------------------
# retire
# ---------------------------------------------------------------------------


def test_retire_demotes_rotating_out_to_retired(
    db, mock_vault, patch_gpg, mirror, seed_distro
):
    service = MirrorSigningKeyService(db)
    service.ensure_active(mirror)
    service.rotate_prepare(mirror)

    h = _make_host(db, seed_distro, "ready-retire.example.com")
    db.add(
        HostMirrorTrust(
            host_id=h.id,
            mirror_id=mirror.id,
            installed_fingerprints=[_ACTIVE_FPR, _PENDING_FPR],
        )
    )
    db.commit()

    service.cutover(mirror)
    rotating = (
        db.query(MirrorSigningKey)
        .filter_by(mirror_repo_id=mirror.id, status="rotating_out")
        .one()
    )
    assert rotating.gpg_fingerprint == _ACTIVE_FPR

    retired = service.retire(mirror.id, rotating.id)
    assert retired.status == "retired"
    assert retired.retired_at is not None


def test_retire_refuses_active_key(db, mock_vault, patch_gpg, mirror):
    service = MirrorSigningKeyService(db)
    active = service.ensure_active(mirror)
    with pytest.raises(RotationError, match="can only retire rotating_out"):
        service.retire(mirror.id, active.id)


def test_retire_refuses_pending_key(db, mock_vault, patch_gpg, mirror):
    service = MirrorSigningKeyService(db)
    service.ensure_active(mirror)
    pending = service.rotate_prepare(mirror)
    with pytest.raises(RotationError, match="can only retire rotating_out"):
        service.retire(mirror.id, pending.id)


def test_retire_404_on_unknown_key(db, mock_vault, patch_gpg, mirror):
    """The not-found path raises ``RotationNotFound``
    specifically (a ``RotationError`` subclass), so the route can map
    by type rather than substring-matching the error text.
    """
    service = MirrorSigningKeyService(db)
    with pytest.raises(RotationNotFound, match="not found for mirror"):
        service.retire(mirror.id, 99999)
    # Subclass relationship preserved for callers that catch the parent.
    assert issubclass(RotationNotFound, RotationError)


def test_retire_404_on_key_for_other_mirror(db, mock_vault, patch_gpg, mirror):
    """A key belonging to mirror A cannot be retired through mirror B's
    endpoint — service-level discriminator.
    """
    other = MirrorRepo(
        slug="other-mirror",
        display_name="Other",
        package_family="deb",
        upstream_url="http://example.com",
        distribution="jammy",
        components='["main"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        verify_upstream_signature=False,
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(other)
    db.commit()

    service = MirrorSigningKeyService(db)
    other_active = service.ensure_active(other)
    # Cross-mirror also raises RotationNotFound (same
    # type as unknown id) so callers can't probe cross-mirror
    # existence by exception class.
    with pytest.raises(RotationNotFound, match="not found for mirror"):
        service.retire(mirror.id, other_active.id)


# ---------------------------------------------------------------------------
# auto_retire_expired
# ---------------------------------------------------------------------------


def test_auto_retire_disabled_when_env_unset(
    db, mock_vault, patch_gpg, mirror, monkeypatch
):
    monkeypatch.delenv("PRAXIS_MIRROR_KEY_AUTO_RETIRE_DAYS", raising=False)
    service = MirrorSigningKeyService(db)
    # Manufacture a rotating_out key past any plausible window.
    row = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status="rotating_out",
        gpg_fingerprint="9" * 40,
        key_uid="aged",
        vault_path=vault_path_for(mirror.slug, "9" * 40),
        cutover_at=datetime.utcnow() - timedelta(days=365),
    )
    db.add(row)
    db.commit()

    assert service.auto_retire_expired() == []
    db.refresh(row)
    assert row.status == "rotating_out"


def test_auto_retire_invalid_env_does_nothing(
    db, mock_vault, patch_gpg, mirror, monkeypatch
):
    monkeypatch.setenv("PRAXIS_MIRROR_KEY_AUTO_RETIRE_DAYS", "not-a-number")
    service = MirrorSigningKeyService(db)
    row = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status="rotating_out",
        gpg_fingerprint="A" * 40,
        key_uid="aged",
        vault_path=vault_path_for(mirror.slug, "A" * 40),
        cutover_at=datetime.utcnow() - timedelta(days=365),
    )
    db.add(row)
    db.commit()
    assert service.auto_retire_expired() == []


def test_auto_retire_picks_up_keys_past_window(
    db, mock_vault, patch_gpg, mirror, monkeypatch
):
    monkeypatch.setenv("PRAXIS_MIRROR_KEY_AUTO_RETIRE_DAYS", "30")
    service = MirrorSigningKeyService(db)

    aged = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status="rotating_out",
        gpg_fingerprint="A" * 40,
        key_uid="aged",
        vault_path=vault_path_for(mirror.slug, "A" * 40),
        cutover_at=datetime.utcnow() - timedelta(days=45),
    )
    fresh = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status="rotating_out",
        gpg_fingerprint="B" * 40,
        key_uid="fresh",
        vault_path=vault_path_for(mirror.slug, "B" * 40),
        cutover_at=datetime.utcnow() - timedelta(days=10),
    )
    db.add_all([aged, fresh])
    db.commit()

    retired_ids = service.auto_retire_expired()
    assert retired_ids == [aged.id]
    db.refresh(aged)
    db.refresh(fresh)
    assert aged.status == "retired"
    assert aged.retired_at is not None
    assert fresh.status == "rotating_out"


def test_auto_retire_scoped_to_mirror_id_when_provided(
    db, mock_vault, patch_gpg, mirror, monkeypatch
):
    """``mirror_id=`` filters the sweep so a per-mirror caller doesn't
    affect rows on other mirrors.
    """
    monkeypatch.setenv("PRAXIS_MIRROR_KEY_AUTO_RETIRE_DAYS", "30")

    other = MirrorRepo(
        slug="other-rotate",
        display_name="Other",
        package_family="deb",
        upstream_url="http://example.com",
        distribution="jammy",
        components='["main"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        verify_upstream_signature=False,
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(other)
    db.commit()

    aged_a = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status="rotating_out",
        gpg_fingerprint="A" * 40,
        key_uid="aged-a",
        vault_path=vault_path_for(mirror.slug, "A" * 40),
        cutover_at=datetime.utcnow() - timedelta(days=45),
    )
    aged_b = MirrorSigningKey(
        mirror_repo_id=other.id,
        status="rotating_out",
        gpg_fingerprint="B" * 40,
        key_uid="aged-b",
        vault_path=vault_path_for(other.slug, "B" * 40),
        cutover_at=datetime.utcnow() - timedelta(days=45),
    )
    db.add_all([aged_a, aged_b])
    db.commit()

    service = MirrorSigningKeyService(db)
    retired_ids = service.auto_retire_expired(mirror_id=mirror.id)
    assert retired_ids == [aged_a.id]
    db.refresh(aged_b)
    assert aged_b.status == "rotating_out"  # other mirror's row untouched
