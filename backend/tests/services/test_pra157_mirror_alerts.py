"""PRA-157 #2b: mirror alert dedup + recovery semantics tests."""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import patch

from app.db.models import MirrorAlertState, MirrorRepo
from app.services import alert_service, mirror_alerts


def test_mirror_event_types_registered_in_supported():
    """The three mirror events must be in ``alert_service.SUPPORTED_EVENT_TYPES``
    so ``/alerts/event-types`` exposes them to the UI dropdown and
    operators can configure alert routing for them. Emission alone isn't enough; events have to be
    discoverable through the normal alert config surface.
    """
    for event_type in (
        "mirror_sync_failed",
        "mirror_sync_completed",
        "mirror_disk_pressure",
    ):
        assert event_type in alert_service.SUPPORTED_EVENT_TYPES, (
            f"{event_type!r} must be registered for alert config UI; "
            "see alert_service.SUPPORTED_EVENT_TYPES"
        )


def _patch_signing_noop(monkeypatch):
    """Replace the orchestrator's signing fence with a noop returning
    a successful ``_SignOutcome`` (PRA-158 #2c).

    PRA-157's alert tests drive ``perform_sync_for_mirror`` end-to-end
    without Vault available; the new signing fence would try to load
    a private key and fail. These tests are about alert semantics, not
    signing, so noop'ing the fence keeps them focused.
    """
    from app.services.mirror_sync import service as svc

    def fake_sign(db, mirror, run, work):  # noqa: ANN001
        # Match the real shape so the orchestrator's step #5 promote
        # call has staged files to move. Stage a manifest+sig pair
        # the same way stage_signed_manifest would (without gpg).
        from app.services.mirror_paths import (
            staged_manifest_dir,
            staged_manifest_path,
            staged_manifest_signature_path,
        )

        staged_manifest_dir(mirror.slug, run.id).mkdir(parents=True, exist_ok=True)
        staged_manifest_path(mirror.slug, run.id).write_bytes(b'{"fake":"manifest"}')
        staged_manifest_signature_path(mirror.slug, run.id).write_bytes(b"fake-sig")
        return svc._SignOutcome(
            ok=True,
            manifest_byte_count=0,
            manifest_package_count=0,
            manifest_sha256_hex="0" * 64,
            signed_with_key_id=None,
        )

    monkeypatch.setattr(svc, "_sign_run_in_work", fake_sign)

    # PRA-158 #4b: orchestrator now runs the upstream-verify gate
    # before signing when verify_upstream_signature=true. These legacy
    # alert tests don't seed mirror_upstream_keys, so without a stub
    # the gate refuses every sync. Patch the verify call to a
    # passthrough — these tests are about alert semantics, not
    # upstream verification.
    from app.services import mirror_upstream_verify

    def fake_verify(db_, mirror, work):  # noqa: ANN001
        return mirror_upstream_verify.UpstreamVerifyResult(ok=True)

    monkeypatch.setattr(
        mirror_upstream_verify, "verify_upstream_signatures", fake_verify
    )


def _make_mirror(db, **overrides) -> MirrorRepo:
    base = dict(
        slug=f"test-alert-{datetime.utcnow().timestamp()}",
        display_name="Alert Mirror",
        package_family="deb",
        upstream_url="http://archive.ubuntu.com/ubuntu",
        distribution="jammy",
        components="[]",
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        enabled=True,
        source_mode="upstream_sync",
        verify_upstream_signature=True,
        retention_keep_count=10,
        retention_keep_within_days=30,
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    base.update(overrides)
    mirror = MirrorRepo(**base)
    db.add(mirror)
    db.flush()
    return mirror


# ---------------------------------------------------------------------------
# maybe_fire_mirror_alert — cooldown + dedup row
# ---------------------------------------------------------------------------


def test_first_failure_fires_and_writes_dedup_row(db):
    mirror = _make_mirror(db, slug="test-first-fail")
    db.commit()

    with patch("app.services.mirror_alerts.alert_service.send_alert") as send:
        fired = mirror_alerts.alert_sync_failed(
            db, mirror, "upstream timeout", now=datetime.utcnow()
        )
    db.commit()

    assert fired is True
    send.assert_called_once()
    args, kwargs = send.call_args
    assert kwargs["event_type"] == "mirror_sync_failed"
    assert kwargs["severity"] == "error"
    assert kwargs["system_id"] is None

    state = (
        db.query(MirrorAlertState)
        .filter(
            MirrorAlertState.mirror_repo_id == mirror.id,
            MirrorAlertState.event_type == "mirror_sync_failed",
        )
        .one()
    )
    assert state.last_fired_at is not None


def test_cooldown_suppresses_repeated_failure(db):
    mirror = _make_mirror(db, slug="test-cooldown")
    db.commit()

    t0 = datetime.utcnow()
    with patch("app.services.mirror_alerts.alert_service.send_alert") as send:
        first = mirror_alerts.alert_sync_failed(db, mirror, "boom 1", now=t0)
        db.commit()

        # 1 hour later — still inside the 24h default cooldown.
        second = mirror_alerts.alert_sync_failed(
            db, mirror, "boom 2", now=t0 + timedelta(hours=1)
        )
        db.commit()

        # 23 hours after first — still inside cooldown.
        third = mirror_alerts.alert_sync_failed(
            db, mirror, "boom 3", now=t0 + timedelta(hours=23)
        )
        db.commit()

    assert first is True
    assert second is False
    assert third is False
    assert send.call_count == 1


def test_cooldown_elapses_then_alerts_again(db):
    mirror = _make_mirror(db, slug="test-cooldown-elapse")
    db.commit()

    t0 = datetime.utcnow()
    with patch("app.services.mirror_alerts.alert_service.send_alert") as send:
        first = mirror_alerts.alert_sync_failed(db, mirror, "boom 1", now=t0)
        db.commit()
        # 25 hours later — past the 24h cooldown.
        second = mirror_alerts.alert_sync_failed(
            db, mirror, "boom 2", now=t0 + timedelta(hours=25)
        )
        db.commit()

    assert first is True
    assert second is True
    assert send.call_count == 2

    # Dedup row's last_fired_at advanced to the second firing.
    state = (
        db.query(MirrorAlertState)
        .filter(
            MirrorAlertState.mirror_repo_id == mirror.id,
            MirrorAlertState.event_type == "mirror_sync_failed",
        )
        .one()
    )
    assert state.last_fired_at == t0 + timedelta(hours=25)


def test_recovery_alert_has_no_cooldown_gate(db):
    """``mirror_sync_completed`` uses cooldown_hours=0 because the
    orchestrator already gates on the failed→ok transition. The
    helper should fire whenever called.
    """
    mirror = _make_mirror(db, slug="test-recovery-no-cooldown")
    db.commit()
    t0 = datetime.utcnow()

    with patch("app.services.mirror_alerts.alert_service.send_alert") as send:
        first = mirror_alerts.alert_sync_completed(db, mirror, now=t0)
        db.commit()
        # 1 minute later — would be inside any meaningful cooldown.
        second = mirror_alerts.alert_sync_completed(
            db, mirror, now=t0 + timedelta(minutes=1)
        )
        db.commit()

    assert first is True
    assert second is True
    assert send.call_count == 2


def test_disk_pressure_has_independent_cooldown_from_sync_failed(db):
    """Cooldown is per-(mirror, event_type), not a global per-mirror
    timer. A mirror_sync_failed firing should not suppress a
    subsequent mirror_disk_pressure firing.
    """
    mirror = _make_mirror(db, slug="test-event-isolation")
    db.commit()
    t0 = datetime.utcnow()

    with patch("app.services.mirror_alerts.alert_service.send_alert") as send:
        sf = mirror_alerts.alert_sync_failed(db, mirror, "fail", now=t0)
        db.commit()
        dp = mirror_alerts.alert_disk_pressure(
            db, mirror, "low free", now=t0 + timedelta(seconds=1)
        )
        db.commit()

    assert sf is True
    assert dp is True
    assert send.call_count == 2

    # Two separate dedup rows.
    rows = (
        db.query(MirrorAlertState)
        .filter(MirrorAlertState.mirror_repo_id == mirror.id)
        .all()
    )
    event_types = {r.event_type for r in rows}
    assert event_types == {"mirror_sync_failed", "mirror_disk_pressure"}


def test_send_alert_failure_still_writes_dedup_row(db):
    """Per PRA-156 lifecycle-emitter semantics, the dedup row records
    'Praxis emitted', not 'external delivery succeeded'. Even if
    send_alert raises (e.g. webhook backoff is unavailable), we still
    mark the attempt to avoid flooding.
    """
    mirror = _make_mirror(db, slug="test-send-raises")
    db.commit()

    def _boom(*_args, **_kw):
        raise RuntimeError("webhook down")

    with patch(
        "app.services.mirror_alerts.alert_service.send_alert", side_effect=_boom
    ):
        fired = mirror_alerts.alert_sync_failed(
            db, mirror, "any", now=datetime.utcnow()
        )
    db.commit()

    assert fired is True  # we *attempted* to fire
    state = (
        db.query(MirrorAlertState)
        .filter(MirrorAlertState.mirror_repo_id == mirror.id)
        .one()
    )
    assert state.event_type == "mirror_sync_failed"


# ---------------------------------------------------------------------------
# Recovery transition gating in perform_sync_for_mirror
# ---------------------------------------------------------------------------


def test_recovery_event_only_built_on_failed_to_ok_transition(
    db, tmp_path, monkeypatch
):
    """End-to-end: ``perform_sync_for_mirror`` builds a
    ``mirror_sync_completed`` event in the returned events list only
    when ``prior_status='failed'``. With the alert/sync transaction-
    decoupling refactor (#2b-a), the orchestrator returns events for
    the caller to dispatch on a fresh session — so we assert on the
    returned events list rather than on send_alert mocks here.
    """
    from app.db.models import MirrorSyncRun
    from app.services import mirror_alerts, mirror_disk
    from app.services.mirror_sync import SyncResult
    from app.services.mirror_sync.service import perform_sync_for_mirror

    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))

    class _OkEngine:
        def sync(self, mirror, work_dir):
            work_dir.mkdir(parents=True, exist_ok=True)
            (work_dir / "x.deb").write_bytes(b"hi")
            return SyncResult(ok=True)

        def estimate_sync_bytes(self, mirror):
            return None

    monkeypatch.setattr(
        "app.services.mirror_sync.service.engine_for", lambda m: _OkEngine()
    )
    monkeypatch.setattr(
        "app.services.mirror_sync.service.check_free_space_gate",
        lambda **_kw: mirror_disk.GateDecision(
            allowed=True, reason="", estimate_unavailable=False
        ),
    )
    _patch_signing_noop(monkeypatch)

    # Case 1: prior_status='failed' → recovery event built.
    m_failed = _make_mirror(db, slug="test-recovery-from-failed")
    db.commit()
    run_failed = MirrorSyncRun(
        mirror_repo_id=m_failed.id,
        started_at=datetime.utcnow(),
        status="running",
    )
    db.add(run_failed)
    db.flush()

    ok_a, events_a = perform_sync_for_mirror(
        db, m_failed, run_failed, prior_status="failed"
    )
    db.commit()
    assert ok_a is True
    event_types_a = [e.event_type for e in events_a]
    assert mirror_alerts.EVENT_SYNC_COMPLETED in event_types_a

    # Case 2: prior_status='idle' → recovery event NOT built.
    m_fresh = _make_mirror(db, slug="test-recovery-from-idle")
    db.commit()
    run_fresh = MirrorSyncRun(
        mirror_repo_id=m_fresh.id,
        started_at=datetime.utcnow(),
        status="running",
    )
    db.add(run_fresh)
    db.flush()

    ok_b, events_b = perform_sync_for_mirror(
        db, m_fresh, run_fresh, prior_status="idle"
    )
    db.commit()
    assert ok_b is True
    event_types_b = [e.event_type for e in events_b]
    assert mirror_alerts.EVENT_SYNC_COMPLETED not in event_types_b


def test_claim_and_sync_full_path_fires_recovery_alert(tmp_path, monkeypatch):
    """End-to-end through ``claim_and_sync_one_mirror``: a mirror
    with prior_status='failed' goes through claim → sync → alert
    dispatch and the recovery alert reaches ``send_alert``.

    Pre-#2b-a, ``perform_sync_for_mirror`` read the prior status
    off the mirror row, but ``_persist_claim_for_mirror`` had
    already mutated it to 'running'. Recovery never fired in
    production. The unit test for ``perform_sync_for_mirror`` did
    not catch this because it bypassed the claim path. This is the
    full-path regression that was called for.

    Uses ``SessionLocal`` directly (not the per-test ``db`` fixture's
    savepoint) because ``claim_and_sync_one_mirror`` opens its own
    fresh SessionLocals across three transactions, and savepoint-
    committed rows aren't visible to those independent connections.
    Explicit cleanup at the end keeps this test isolated.
    """
    from app.db.models import MirrorAlertState, MirrorRepo, MirrorSyncRun
    from app.db.session import SessionLocal
    from app.services import mirror_disk
    from app.services.mirror_sweep import claim_and_sync_one_mirror
    from app.services.mirror_sync import SyncResult

    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))

    class _OkEngine:
        def sync(self, mirror, work_dir):
            work_dir.mkdir(parents=True, exist_ok=True)
            (work_dir / "x.deb").write_bytes(b"hi")
            return SyncResult(ok=True)

        def estimate_sync_bytes(self, mirror):
            return None

    monkeypatch.setattr(
        "app.services.mirror_sync.service.engine_for", lambda m: _OkEngine()
    )
    monkeypatch.setattr(
        "app.services.mirror_sync.service.check_free_space_gate",
        lambda **_kw: mirror_disk.GateDecision(
            allowed=True, reason="", estimate_unavailable=False
        ),
    )
    _patch_signing_noop(monkeypatch)

    slug = f"test-fullpath-recovery-{datetime.utcnow().timestamp()}"
    setup_db = SessionLocal()
    try:
        mirror = MirrorRepo(
            slug=slug,
            display_name="Full-path recovery test",
            package_family="deb",
            upstream_url="http://archive.ubuntu.com/ubuntu",
            distribution="jammy",
            components="[]",
            architectures='["amd64"]',
            sync_schedule_cron="0 2 * * *",
            enabled=True,
            source_mode="upstream_sync",
            verify_upstream_signature=True,
            retention_keep_count=10,
            retention_keep_within_days=30,
            last_sync_status="failed",  # the prior status that should fire recovery
            current_disk_bytes=0,
        )
        setup_db.add(mirror)
        setup_db.commit()
        mirror_id = mirror.id
    finally:
        setup_db.close()

    try:
        with patch("app.services.mirror_alerts.alert_service.send_alert") as send:
            outcome = claim_and_sync_one_mirror(mirror_id, slug)

        assert outcome == "ok"

        fired_events = [c.kwargs["event_type"] for c in send.call_args_list]
        assert mirror_alerts.EVENT_SYNC_COMPLETED in fired_events, (
            f"recovery alert did not reach send_alert through the full "
            f"claim → sync → alert pipeline; saw events: {fired_events}"
        )
    finally:
        cleanup_db = SessionLocal()
        try:
            cleanup_db.query(MirrorAlertState).filter(
                MirrorAlertState.mirror_repo_id == mirror_id
            ).delete()
            cleanup_db.query(MirrorSyncRun).filter(
                MirrorSyncRun.mirror_repo_id == mirror_id
            ).delete()
            cleanup_db.query(MirrorRepo).filter(MirrorRepo.id == mirror_id).delete()
            cleanup_db.commit()
        finally:
            cleanup_db.close()


def test_imported_offline_full_path_yields_ineligible(tmp_path, monkeypatch):
    """End-to-end through ``claim_and_sync_one_mirror``: a mirror
    with ``source_mode='imported_offline'`` is refused at the
    eligibility recheck inside ``_persist_claim_for_mirror``. The
    sweep filter + on-demand 409 preflight already catch it, but
    the recheck under the lock guarantees correctness even when
    state changes between enumeration and claim. PRA-157 #4 E2E
    coverage.
    """
    from app.db.models import MirrorAlertState, MirrorRepo, MirrorSyncRun
    from app.db.session import SessionLocal
    from app.services.mirror_sweep import claim_and_sync_one_mirror

    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))

    slug = f"test-imported-{datetime.utcnow().timestamp()}"
    setup_db = SessionLocal()
    try:
        mirror = MirrorRepo(
            slug=slug,
            display_name="Imported-offline",
            package_family="deb",
            upstream_url="http://archive.ubuntu.com/ubuntu",
            distribution="jammy",
            components="[]",
            architectures='["amd64"]',
            sync_schedule_cron="0 2 * * *",
            enabled=True,
            source_mode="imported_offline",
            verify_upstream_signature=True,
            retention_keep_count=10,
            retention_keep_within_days=30,
            last_sync_status="idle",
            current_disk_bytes=0,
        )
        setup_db.add(mirror)
        setup_db.commit()
        mirror_id = mirror.id
    finally:
        setup_db.close()

    try:
        outcome = claim_and_sync_one_mirror(mirror_id, slug)
        assert outcome == "ineligible"

        check_db = SessionLocal()
        try:
            runs = (
                check_db.query(MirrorSyncRun)
                .filter(MirrorSyncRun.mirror_repo_id == mirror_id)
                .all()
            )
            alerts = (
                check_db.query(MirrorAlertState)
                .filter(MirrorAlertState.mirror_repo_id == mirror_id)
                .all()
            )
            assert runs == []
            assert alerts == []
        finally:
            check_db.close()
    finally:
        cleanup_db = SessionLocal()
        try:
            cleanup_db.query(MirrorAlertState).filter(
                MirrorAlertState.mirror_repo_id == mirror_id
            ).delete()
            cleanup_db.query(MirrorSyncRun).filter(
                MirrorSyncRun.mirror_repo_id == mirror_id
            ).delete()
            cleanup_db.query(MirrorRepo).filter(MirrorRepo.id == mirror_id).delete()
            cleanup_db.commit()
        finally:
            cleanup_db.close()


def test_five_consecutive_failures_produce_one_alert_within_cooldown(
    tmp_path, monkeypatch
):
    """End-to-end through ``claim_and_sync_one_mirror``: 5 failed
    syncs within the 24h cooldown window produce exactly 1
    ``mirror_sync_failed`` alert. The 2nd-5th attempts hit the
    dedup cooldown via mirror_alert_state. PRA-157 #4 E2E coverage
    of the cooldown contract.
    """
    from app.db.models import MirrorAlertState, MirrorRepo, MirrorSyncRun
    from app.db.session import SessionLocal
    from app.services import mirror_disk
    from app.services.mirror_sweep import claim_and_sync_one_mirror
    from app.services.mirror_sync import SyncResult

    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))

    class _AlwaysFailEngine:
        def sync(self, mirror, work_dir):
            return SyncResult(ok=False, error_text="upstream is broken")

        def estimate_sync_bytes(self, mirror):
            return None

    monkeypatch.setattr(
        "app.services.mirror_sync.service.engine_for",
        lambda m: _AlwaysFailEngine(),
    )
    monkeypatch.setattr(
        "app.services.mirror_sync.service.check_free_space_gate",
        lambda **_kw: mirror_disk.GateDecision(
            allowed=True, reason="", estimate_unavailable=False
        ),
    )

    slug = f"test-cooldown-e2e-{datetime.utcnow().timestamp()}"
    setup_db = SessionLocal()
    try:
        mirror = MirrorRepo(
            slug=slug,
            display_name="Cooldown E2E",
            package_family="deb",
            upstream_url="http://archive.ubuntu.com/ubuntu",
            distribution="jammy",
            components="[]",
            architectures='["amd64"]',
            sync_schedule_cron="0 2 * * *",
            enabled=True,
            source_mode="upstream_sync",
            verify_upstream_signature=True,
            retention_keep_count=10,
            retention_keep_within_days=30,
            last_sync_status="idle",
            current_disk_bytes=0,
        )
        setup_db.add(mirror)
        setup_db.commit()
        mirror_id = mirror.id
    finally:
        setup_db.close()

    try:
        with patch("app.services.mirror_alerts.alert_service.send_alert") as send:
            for _ in range(5):
                outcome = claim_and_sync_one_mirror(mirror_id, slug)
                assert outcome == "failed"

        fired = [c.kwargs["event_type"] for c in send.call_args_list]
        assert (
            fired.count("mirror_sync_failed") == 1
        ), f"expected 1 sync_failed alert, got {fired}"

        check_db = SessionLocal()
        try:
            runs = (
                check_db.query(MirrorSyncRun)
                .filter(MirrorSyncRun.mirror_repo_id == mirror_id)
                .all()
            )
            assert len(runs) == 5
            assert all(r.status == "failed" for r in runs)
        finally:
            check_db.close()
    finally:
        cleanup_db = SessionLocal()
        try:
            cleanup_db.query(MirrorAlertState).filter(
                MirrorAlertState.mirror_repo_id == mirror_id
            ).delete()
            cleanup_db.query(MirrorSyncRun).filter(
                MirrorSyncRun.mirror_repo_id == mirror_id
            ).delete()
            cleanup_db.query(MirrorRepo).filter(MirrorRepo.id == mirror_id).delete()
            cleanup_db.commit()
        finally:
            cleanup_db.close()
