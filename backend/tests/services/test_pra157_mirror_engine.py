"""PRA-157 slice #1: mirror engine scaffolding tests.

Covers the worker-safe scheduler claim primitive, stale-running
recovery, the cron-due helper, the praxis-mirror.json descriptor
writer, and the service-level invariant for ``mirror_sync_runs``
(``status='ok'`` ⇒ manifest fields present).

The actual sync engines (debmirror in slice #2a, dnf reposync in
slice #3) are NOT exercised here — slice #1 NOOPs the subprocess
body after stale recovery.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta

import pytest

from app.db.models import MirrorRepo, MirrorSyncRun
from app.services import mirror_paths
from app.services.mirror_lock import MIRROR_LOCK_NAMESPACE, claim_mirror_for_sync
from app.services.mirror_sweep import (
    ClaimResult,
    _persist_claim_for_mirror,
    _stale_recover_running_runs_for_mirror,
)
from app.services.scheduler_service import _mirror_due

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mirror(db, **overrides) -> MirrorRepo:
    base = dict(
        slug=f"test-{datetime.utcnow().timestamp()}",
        display_name="Test Mirror",
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
# Advisory lock — multi-worker contention + release
# ---------------------------------------------------------------------------


def test_lock_loser_skips_promptly():
    """Two threads race for the same advisory lock; one wins, the
    other returns ``False`` quickly without blocking. Guards against
    accidental regression to a blocking ``pg_advisory_lock`` call.
    """
    # No DB row needed — pg_try_advisory_lock keys off arbitrary ints.
    fake_id = 999_999

    barrier = threading.Barrier(2)
    results: dict[str, tuple[bool, float]] = {}

    def worker(name: str, hold_seconds: float) -> None:
        barrier.wait()
        start = time.monotonic()
        with claim_mirror_for_sync(fake_id) as acquired:
            elapsed = time.monotonic() - start
            results[name] = (acquired, elapsed)
            if acquired:
                # Hold the lock briefly so the other thread definitely
                # races against a held lock, not a window where it's
                # already released.
                time.sleep(hold_seconds)

    t_a = threading.Thread(target=worker, args=("a", 0.5))
    t_b = threading.Thread(target=worker, args=("b", 0.5))
    t_a.start()
    t_b.start()
    t_a.join(timeout=5)
    t_b.join(timeout=5)

    assert "a" in results and "b" in results
    a_acquired, _ = results["a"]
    b_acquired, _ = results["b"]
    # Exactly one acquired.
    assert (a_acquired, b_acquired) in [(True, False), (False, True)]
    # Loser returned far before the winner's 0.5s hold elapsed.
    loser = "a" if not a_acquired else "b"
    _, loser_elapsed = results[loser]
    assert (
        loser_elapsed < 0.2
    ), f"loser took {loser_elapsed:.3f}s — looks blocking, not pg_try_*"


def test_lock_released_after_winner_exits():
    """Sequential acquire after first holder exits succeeds."""
    fake_id = 999_998

    with claim_mirror_for_sync(fake_id) as first:
        assert first is True

    # Lock should be released — second acquire succeeds.
    with claim_mirror_for_sync(fake_id) as second:
        assert second is True


def test_lock_namespace_is_documented_constant():
    # Guards against accidental rebase that drops the namespace
    # constant or changes its value silently.
    assert MIRROR_LOCK_NAMESPACE == 0x4D52


# ---------------------------------------------------------------------------
# Stale-running recovery
# ---------------------------------------------------------------------------


def test_stale_recovery_marks_running_as_failed(db):
    mirror = _make_mirror(db, slug="test-stale-recovery")
    db.commit()

    backdated = datetime.utcnow() - timedelta(hours=2)
    run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=backdated,
        status="running",
    )
    db.add(run)
    db.commit()

    now = datetime.utcnow()
    n = _stale_recover_running_runs_for_mirror(db, mirror.id, now)
    db.commit()

    assert n == 1
    db.refresh(run)
    assert run.status == "failed"
    assert run.finished_at == now
    assert "stale" in (run.error_text or "").lower()


def test_stale_recovery_idempotent_when_no_running(db):
    mirror = _make_mirror(db, slug="test-stale-noop")
    db.commit()

    now = datetime.utcnow()
    assert _stale_recover_running_runs_for_mirror(db, mirror.id, now) == 0

    # Add an OK row — recovery must not touch it.
    ok = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=datetime.utcnow() - timedelta(minutes=5),
        finished_at=datetime.utcnow(),
        status="ok",
        manifest_sha256="0" * 64,
        manifest_path="/dev/null",
        byte_count=0,
        package_count=0,
    )
    db.add(ok)
    db.commit()

    assert _stale_recover_running_runs_for_mirror(db, mirror.id, now) == 0
    db.refresh(ok)
    assert ok.status == "ok"


def test_stale_recovery_only_touches_target_mirror(db):
    """Sibling mirror's running row is not affected."""
    target = _make_mirror(db, slug="test-stale-target")
    sibling = _make_mirror(db, slug="test-stale-sibling")
    db.commit()

    backdated = datetime.utcnow() - timedelta(hours=2)
    target_run = MirrorSyncRun(
        mirror_repo_id=target.id, started_at=backdated, status="running"
    )
    sibling_run = MirrorSyncRun(
        mirror_repo_id=sibling.id, started_at=backdated, status="running"
    )
    db.add_all([target_run, sibling_run])
    db.commit()

    n = _stale_recover_running_runs_for_mirror(db, target.id, datetime.utcnow())
    db.commit()

    assert n == 1
    db.refresh(target_run)
    db.refresh(sibling_run)
    assert target_run.status == "failed"
    assert sibling_run.status == "running"


# ---------------------------------------------------------------------------
# Persist-claim helper (P2-α)
# ---------------------------------------------------------------------------


def test_persist_claim_creates_running_run_and_state(db):
    """One claim ⇒ exactly one running run row + mirror state update.
    Closes the gap pre-α the claim path stale-failed
    prior runs and logged but never persisted forward state.
    """
    mirror = _make_mirror(db, slug="test-claim-persist")
    db.commit()
    now = datetime.utcnow()

    result = _persist_claim_for_mirror(db, mirror.id, now, cap=10)
    db.commit()

    assert result.outcome == "slot_taken"
    assert result.run_id is not None
    assert isinstance(result.run_id, int)

    runs = (
        db.query(MirrorSyncRun).filter(MirrorSyncRun.mirror_repo_id == mirror.id).all()
    )
    assert len(runs) == 1
    assert runs[0].id == result.run_id
    assert runs[0].status == "running"
    assert runs[0].started_at == now
    assert runs[0].finished_at is None
    assert runs[0].manifest_sha256 is None

    db.refresh(mirror)
    assert mirror.last_sync_status == "running"
    assert mirror.last_sync_started_at == now


def test_persist_claim_stale_recovers_then_inserts(db):
    """Stale prior running row → marked failed, AND a new running row
    is inserted in the same call. Atomic from the caller's view.
    """
    mirror = _make_mirror(db, slug="test-claim-stale-and-insert")
    db.commit()

    backdated = datetime.utcnow() - timedelta(hours=2)
    stale = MirrorSyncRun(
        mirror_repo_id=mirror.id, started_at=backdated, status="running"
    )
    db.add(stale)
    db.commit()

    now = datetime.utcnow()
    result = _persist_claim_for_mirror(db, mirror.id, now, cap=10)
    assert result.outcome == "slot_taken"
    db.commit()

    db.refresh(stale)
    assert stale.status == "failed"
    assert "stale" in (stale.error_text or "").lower()

    fresh = (
        db.query(MirrorSyncRun)
        .filter(
            MirrorSyncRun.mirror_repo_id == mirror.id,
            MirrorSyncRun.status == "running",
        )
        .all()
    )
    assert len(fresh) == 1
    assert fresh[0].started_at == now


def test_persist_claim_refuses_when_global_cap_reached(db):
    """Cap=2 + 2 running rows already → claim refused, no new row,
    no mirror state mutation. The stale recovery for our mirror still
    runs (idempotent — no orphans here since we have no running row
    of our own yet).
    """
    target = _make_mirror(db, slug="test-claim-capped")
    busy_a = _make_mirror(db, slug="test-claim-busy-a")
    busy_b = _make_mirror(db, slug="test-claim-busy-b")
    db.commit()

    started = datetime.utcnow() - timedelta(minutes=5)
    db.add_all(
        [
            MirrorSyncRun(
                mirror_repo_id=busy_a.id, started_at=started, status="running"
            ),
            MirrorSyncRun(
                mirror_repo_id=busy_b.id, started_at=started, status="running"
            ),
        ]
    )
    db.commit()

    target_status_before = target.last_sync_status
    target_started_before = target.last_sync_started_at

    now = datetime.utcnow()
    result = _persist_claim_for_mirror(db, target.id, now, cap=2)
    db.commit()

    assert result.outcome == "cap_reached"
    assert result.run_id is None

    target_runs = (
        db.query(MirrorSyncRun).filter(MirrorSyncRun.mirror_repo_id == target.id).all()
    )
    assert target_runs == [], "no new run row when cap reached"

    db.refresh(target)
    assert target.last_sync_status == target_status_before
    assert target.last_sync_started_at == target_started_before


def test_persist_claim_flushes_stale_before_counting_cap(db):
    """With production-equivalent autoflush=False semantics, stale
    recovery must reach the DB before the cap count — otherwise the
    count sees the stale row as still 'running' and refuses the slot.

    Bug case caught by cap=1 + 1 stale running row
    for the target mirror → naive count() under autoflush=False sees
    1 running globally → refuses the slot, even though the slot is
    functionally free once the stale recovery commits. Production
    SessionLocal is autoflush=False (db/session.py:67); PRA-170
    flipped the per-test db fixture to autoflush=False so it matches
    prod. The ``db.no_autoflush`` wrapper here is a defense-in-depth
    belt: it still guarantees prod-equivalent semantics even if a
    future contributor flips the fixture default back to True.
    """
    mirror = _make_mirror(db, slug="test-claim-flush-stale")
    db.commit()

    stale = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=datetime.utcnow() - timedelta(hours=2),
        status="running",
    )
    db.add(stale)
    db.commit()

    now = datetime.utcnow()
    with db.no_autoflush:
        result = _persist_claim_for_mirror(db, mirror.id, now, cap=1)
    db.commit()

    assert result.outcome == "slot_taken", (
        "stale row must be flushed to DB before cap count — without "
        "the explicit flush() the count would see the stale row as "
        "still 'running' and refuse the slot under cap=1"
    )
    assert result.run_id is not None

    db.refresh(stale)
    assert stale.status == "failed"

    running_globally = (
        db.query(MirrorSyncRun).filter(MirrorSyncRun.status == "running").all()
    )
    assert len(running_globally) == 1
    assert running_globally[0].started_at == now


def test_persist_claim_returns_ineligible_when_mirror_disappeared(db):
    """If the mirror row vanished between enumeration and persist,
    return outcome='ineligible' rather than letting an FK-violating
    insert blow up at commit.
    """
    mirror = _make_mirror(db, slug="test-claim-disappeared")
    db.commit()
    mirror_id = mirror.id

    db.delete(mirror)
    db.commit()

    result = _persist_claim_for_mirror(db, mirror_id, datetime.utcnow(), cap=10)
    assert result.outcome == "ineligible"
    assert result.run_id is None

    runs = (
        db.query(MirrorSyncRun).filter(MirrorSyncRun.mirror_repo_id == mirror_id).all()
    )
    assert runs == []


def test_persist_claim_returns_ineligible_when_soft_deleted(db):
    """PRA-157 #2b-a: re-check eligibility under the gate. Operator
    soft-deletes between enumeration and claim → outcome='ineligible'.
    """
    mirror = _make_mirror(db, slug="test-claim-soft-deleted")
    db.commit()
    mirror.deleted_at = datetime.utcnow()
    db.commit()

    result = _persist_claim_for_mirror(db, mirror.id, datetime.utcnow(), cap=10)
    assert result.outcome == "ineligible"
    assert result.run_id is None
    runs = (
        db.query(MirrorSyncRun).filter(MirrorSyncRun.mirror_repo_id == mirror.id).all()
    )
    assert runs == []


def test_persist_claim_returns_ineligible_when_disabled(db):
    mirror = _make_mirror(db, slug="test-claim-disabled", enabled=False)
    db.commit()

    result = _persist_claim_for_mirror(db, mirror.id, datetime.utcnow(), cap=10)
    assert result.outcome == "ineligible"


def test_persist_claim_returns_ineligible_when_imported_offline(db):
    mirror = _make_mirror(
        db, slug="test-claim-imported", source_mode="imported_offline"
    )
    db.commit()

    result = _persist_claim_for_mirror(db, mirror.id, datetime.utcnow(), cap=10)
    assert result.outcome == "ineligible"


def test_persist_claim_captures_prior_status_before_mutating_to_running(db):
    """The recovery-alert transition gate needs the mirror's status
    BEFORE this claim mutates it to 'running'. Persist must capture
    that.
    """
    mirror = _make_mirror(db, slug="test-claim-prior-status", last_sync_status="failed")
    db.commit()

    result = _persist_claim_for_mirror(db, mirror.id, datetime.utcnow(), cap=10)
    db.commit()
    assert result.outcome == "slot_taken"
    assert result.prior_status == "failed"

    # And after persist runs, the mirror is in 'running'.
    db.refresh(mirror)
    assert mirror.last_sync_status == "running"


def test_persist_claim_takes_last_slot(db):
    """Cap=2 + 1 running row → 1 slot left → claim succeeds."""
    target = _make_mirror(db, slug="test-claim-last-slot")
    busy = _make_mirror(db, slug="test-claim-one-busy")
    db.commit()

    db.add(
        MirrorSyncRun(
            mirror_repo_id=busy.id,
            started_at=datetime.utcnow() - timedelta(minutes=5),
            status="running",
        )
    )
    db.commit()

    now = datetime.utcnow()
    result = _persist_claim_for_mirror(db, target.id, now, cap=2)
    assert result.outcome == "slot_taken"
    assert result.run_id is not None
    db.commit()

    db.refresh(target)
    assert target.last_sync_status == "running"


# ---------------------------------------------------------------------------
# Cron-due helper
# ---------------------------------------------------------------------------


def test_mirror_due_first_time_fires(db):
    """A mirror with no last_sync_started_at is always due."""
    mirror = _make_mirror(db, slug="test-due-first", sync_schedule_cron="0 2 * * *")
    assert _mirror_due(mirror, datetime.utcnow()) is True


def test_mirror_due_invalid_cron_returns_false(db):
    """Defensive parsing — a malformed schedule is logged and skipped,
    not allowed to crash the whole sweep.
    """
    mirror = _make_mirror(db, slug="test-due-bad-cron", sync_schedule_cron="not a cron")
    assert _mirror_due(mirror, datetime.utcnow()) is False


def test_mirror_due_recent_sync_not_due(db):
    """Daily cron + last sync 1 minute ago → not due."""
    mirror = _make_mirror(
        db,
        slug="test-due-recent",
        sync_schedule_cron="0 2 * * *",  # daily 02:00 UTC
        last_sync_started_at=datetime.utcnow() - timedelta(minutes=1),
    )
    assert _mirror_due(mirror, datetime.utcnow()) is False


# ---------------------------------------------------------------------------
# Descriptor file
# ---------------------------------------------------------------------------


def test_ensure_descriptor_creates_file(tmp_path, monkeypatch):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))

    mirror_paths.ensure_descriptor()

    descriptor = tmp_path / mirror_paths.DESCRIPTOR_FILENAME
    assert descriptor.exists()
    body = json.loads(descriptor.read_text())
    assert body["praxis_mirror_layout"] == mirror_paths.LAYOUT_VERSION
    assert "created_at" in body
    assert "description" in body


def test_ensure_descriptor_idempotent(tmp_path, monkeypatch):
    """Second call doesn't overwrite — first writer wins."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))

    mirror_paths.ensure_descriptor()
    descriptor = tmp_path / mirror_paths.DESCRIPTOR_FILENAME
    first_body = descriptor.read_text()

    mirror_paths.ensure_descriptor()
    second_body = descriptor.read_text()

    assert first_body == second_body


def test_ensure_descriptor_warns_on_layout_mismatch(tmp_path, monkeypatch):
    """If a descriptor exists with a different praxis_mirror_layout,
    log a warning rather than silently leaving the mismatch in place.
    P2-α refinement — silent drift would make
    PRA-160 importer debugging painful.

    Patches ``mirror_paths.logger.warning`` directly via
    ``unittest.mock`` rather than going through pytest's caplog
    fixture or attached handlers. Logging-state coupling under
    full-suite ordering proved brittle (empty captures despite the
    warning code path executing); patching the bound method tests
    the behavior we actually care about — "the mismatch branch
    called .warning with the stale and expected versions" — without
    coupling to process-global logger state.
    """
    from unittest.mock import patch

    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    descriptor = tmp_path / mirror_paths.DESCRIPTOR_FILENAME
    descriptor.write_text(
        json.dumps(
            {
                "praxis_mirror_layout": "v999",
                "created_at": "2099-01-01T00:00:00+00:00",
            }
        )
    )

    with patch.object(mirror_paths.logger, "warning") as warn:
        mirror_paths.ensure_descriptor()

    # File left in place (first writer wins).
    assert json.loads(descriptor.read_text())["praxis_mirror_layout"] == "v999"
    # Warning fired exactly once with the stale + expected versions in args.
    warn.assert_called_once()
    call_args = warn.call_args.args
    assert "layout mismatch" in call_args[0], call_args
    assert "v999" in call_args, call_args
    assert mirror_paths.LAYOUT_VERSION in call_args, call_args


def test_ensure_descriptor_creates_root_if_missing(tmp_path, monkeypatch):
    """Fresh volume mount: root dir doesn't exist yet, ensure_descriptor
    creates it. Regression guard against the Dockerfile ownership-prep
    pattern drifting (recordings volume precedent).
    """
    fresh_root = tmp_path / "fresh"
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(fresh_root))

    assert not fresh_root.exists()
    mirror_paths.ensure_descriptor()
    assert fresh_root.is_dir()
    assert (fresh_root / mirror_paths.DESCRIPTOR_FILENAME).exists()


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def test_path_helpers_compose_correctly(tmp_path, monkeypatch):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))

    assert mirror_paths.mirror_root() == tmp_path
    assert mirror_paths.mirror_repo_root("foo") == tmp_path / "foo"
    assert mirror_paths.work_dir("foo") == tmp_path / "foo" / "work"
    assert mirror_paths.live_dir("foo") == tmp_path / "foo" / "live"
    assert (
        mirror_paths.snapshot_manifest_path("foo", 42)
        == tmp_path / "foo" / "snapshots" / "42.manifest.json"
    )
    assert mirror_paths.sync_lock_path("foo") == tmp_path / "foo" / "sync.lock"
    assert mirror_paths.last_error_path("foo") == tmp_path / "foo" / ".last-error"
    assert mirror_paths.descriptor_path() == tmp_path / mirror_paths.DESCRIPTOR_FILENAME


# ---------------------------------------------------------------------------
# Service-level invariant: status='ok' ⇒ manifest fields present
# ---------------------------------------------------------------------------


def _ok_invariant_holds(run: MirrorSyncRun) -> bool:
    """Locked invariant. Slice #2a will hoist this into a service
    helper that runs on every status transition; slice #1 documents
    it via this test predicate.
    """
    if run.status != "ok":
        return True
    return (
        run.manifest_sha256 is not None
        and run.manifest_path is not None
        and run.byte_count is not None
        and run.package_count is not None
        and run.finished_at is not None
    )


@pytest.mark.parametrize(
    "fields,should_hold",
    [
        # Valid ok row.
        (
            dict(
                status="ok",
                finished_at=datetime.utcnow(),
                manifest_sha256="0" * 64,
                manifest_path="/x",
                byte_count=1,
                package_count=1,
            ),
            True,
        ),
        # Running rows — invariant trivially holds.
        (dict(status="running"), True),
        # Failed rows — invariant trivially holds (manifest fields null).
        (
            dict(
                status="failed",
                finished_at=datetime.utcnow(),
                error_text="boom",
            ),
            True,
        ),
        # ok row missing manifest_sha256 — violation.
        (
            dict(
                status="ok",
                finished_at=datetime.utcnow(),
                manifest_path="/x",
                byte_count=1,
                package_count=1,
            ),
            False,
        ),
        # ok row missing finished_at — violation.
        (
            dict(
                status="ok",
                manifest_sha256="0" * 64,
                manifest_path="/x",
                byte_count=1,
                package_count=1,
            ),
            False,
        ),
    ],
)
def test_ok_invariant(db, fields, should_hold):
    mirror = _make_mirror(db, slug=f"test-inv-{should_hold}-{fields.get('status')}")
    db.flush()

    run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=datetime.utcnow(),
        **fields,
    )
    assert _ok_invariant_holds(run) is should_hold
