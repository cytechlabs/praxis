"""PRA-157 #4: retention policy tests.

Retention is manifest-only in this slice — drops mirror_sync_runs
rows and their on-disk manifest JSON files. Bytes under
work/ and live/ are NOT touched (PRA-159 owns byte-level
immutability when channels need it).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from app.db.models import MirrorRepo, MirrorSyncRun
from app.services.mirror_retention import apply_retention_for_mirror


def _make_mirror(db, **overrides) -> MirrorRepo:
    base = dict(
        slug=f"test-retention-{datetime.utcnow().timestamp()}",
        display_name="Retention test",
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


def _add_ok_run(
    db,
    mirror,
    *,
    idx: int,
    finished_at: datetime,
    manifest_path=None,
    manifest_signature_path=None,
) -> MirrorSyncRun:
    run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=finished_at - timedelta(minutes=5),
        finished_at=finished_at,
        status="ok",
        byte_count=100 * idx,
        package_count=idx,
        manifest_sha256="0" * 64,
        manifest_path=str(manifest_path) if manifest_path else None,
        manifest_signature_path=(
            str(manifest_signature_path) if manifest_signature_path else None
        ),
    )
    db.add(run)
    db.flush()
    return run


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_retention_noop_when_no_ok_runs(db):
    mirror = _make_mirror(db, slug="test-ret-empty")
    db.commit()
    result = apply_retention_for_mirror(db, mirror, now=datetime.utcnow())
    assert result.dropped_run_ids == []
    assert result.manifest_files_unlinked == 0


def test_retention_keeps_single_ok_run_under_aggressive_policy(db):
    """With the most aggressive schema-allowed policy
    (``keep_count=1, keep_within_days=0``), a sole ok run is kept.
    The most-recent-ok floor inside ``apply_retention_for_mirror``
    backstops this even if the schema CHECK constraint is ever
    relaxed to allow keep_count=0.
    """
    mirror = _make_mirror(
        db,
        slug="test-ret-floor",
        retention_keep_count=1,
        retention_keep_within_days=0,
    )
    db.commit()
    run = _add_ok_run(db, mirror, idx=1, finished_at=datetime.utcnow())
    db.commit()

    result = apply_retention_for_mirror(db, mirror, now=datetime.utcnow())
    assert result.dropped_run_ids == []

    db.refresh(run)
    assert run.id is not None  # still there


def test_retention_keep_count_drops_oldest(db):
    mirror = _make_mirror(
        db,
        slug="test-ret-count",
        retention_keep_count=2,
        retention_keep_within_days=0,
    )
    db.commit()
    base = datetime.utcnow() - timedelta(hours=10)
    runs = [
        _add_ok_run(db, mirror, idx=i, finished_at=base + timedelta(minutes=i))
        for i in range(1, 6)  # 5 ok runs
    ]
    db.commit()

    result = apply_retention_for_mirror(db, mirror, now=datetime.utcnow())

    # Keep 2 most-recent + most-recent-floor (which is also one of the
    # top-2). Drop oldest 3.
    assert len(result.dropped_run_ids) == 3
    dropped_set = set(result.dropped_run_ids)
    assert {runs[0].id, runs[1].id, runs[2].id} == dropped_set
    db.commit()

    remaining = (
        db.query(MirrorSyncRun).filter(MirrorSyncRun.mirror_repo_id == mirror.id).all()
    )
    remaining_ids = {r.id for r in remaining}
    assert remaining_ids == {runs[3].id, runs[4].id}


def test_retention_keep_within_days_drops_old(db):
    """keep_count=1 + keep_within_days=30 — the time window keeps
    everything within 30d; older rows outside the count-of-1 are
    dropped.
    """
    mirror = _make_mirror(
        db,
        slug="test-ret-days",
        retention_keep_count=1,
        retention_keep_within_days=30,
    )
    db.commit()
    now = datetime.utcnow()
    fresh_a = _add_ok_run(db, mirror, idx=1, finished_at=now - timedelta(days=5))
    fresh_b = _add_ok_run(db, mirror, idx=2, finished_at=now - timedelta(days=15))
    old_a = _add_ok_run(db, mirror, idx=3, finished_at=now - timedelta(days=45))
    old_b = _add_ok_run(db, mirror, idx=4, finished_at=now - timedelta(days=90))
    # Most-recent-finished — guaranteed kept by the floor regardless
    # of policy.
    most_recent = _add_ok_run(db, mirror, idx=5, finished_at=now)
    db.commit()

    result = apply_retention_for_mirror(db, mirror, now=now)

    dropped = set(result.dropped_run_ids)
    assert old_a.id in dropped
    assert old_b.id in dropped
    assert fresh_a.id not in dropped
    assert fresh_b.id not in dropped
    assert most_recent.id not in dropped


def test_retention_union_of_count_and_days(db):
    """A row inside EITHER keep_count or keep_within_days is kept."""
    mirror = _make_mirror(
        db,
        slug="test-ret-union",
        retention_keep_count=2,
        retention_keep_within_days=30,
    )
    db.commit()
    now = datetime.utcnow()
    # 5 runs: oldest 3 are >30 days ago AND outside top-2 → dropped.
    # Most recent 2 are kept by count. Actually let's mix:
    #   r1: 90 days ago, 5th newest → drop
    #   r2: 60 days ago, 4th newest → drop
    #   r3: 5 days ago, 3rd newest → KEPT by within-days
    #   r4: 1 day ago, 2nd newest → KEPT by both
    #   r5: now,        newest    → KEPT by both + floor
    runs = [
        _add_ok_run(db, mirror, idx=1, finished_at=now - timedelta(days=90)),
        _add_ok_run(db, mirror, idx=2, finished_at=now - timedelta(days=60)),
        _add_ok_run(db, mirror, idx=3, finished_at=now - timedelta(days=5)),
        _add_ok_run(db, mirror, idx=4, finished_at=now - timedelta(days=1)),
        _add_ok_run(db, mirror, idx=5, finished_at=now),
    ]
    db.commit()

    result = apply_retention_for_mirror(db, mirror, now=now)

    dropped = set(result.dropped_run_ids)
    assert dropped == {runs[0].id, runs[1].id}
    kept_remaining = {
        r.id
        for r in db.query(MirrorSyncRun)
        .filter(MirrorSyncRun.mirror_repo_id == mirror.id)
        .all()
    }
    assert kept_remaining == {runs[2].id, runs[3].id, runs[4].id}


def test_retention_excludes_failed_and_running_rows(db):
    """Retention math touches only ok rows. Failed rows stay for
    forensics; running rows are stale-recovered by the claim path.
    """
    mirror = _make_mirror(
        db,
        slug="test-ret-only-ok",
        retention_keep_count=1,
        retention_keep_within_days=0,
    )
    db.commit()
    now = datetime.utcnow()
    ok_old = _add_ok_run(db, mirror, idx=1, finished_at=now - timedelta(days=5))
    ok_new = _add_ok_run(db, mirror, idx=2, finished_at=now)
    failed_row = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=now - timedelta(days=3),
        finished_at=now - timedelta(days=3),
        status="failed",
        error_text="upstream broke",
    )
    running_row = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=now - timedelta(minutes=1),
        status="running",
    )
    db.add_all([failed_row, running_row])
    db.commit()

    result = apply_retention_for_mirror(db, mirror, now=now)

    assert ok_old.id in result.dropped_run_ids
    assert ok_new.id not in result.dropped_run_ids
    db.commit()

    remaining = (
        db.query(MirrorSyncRun).filter(MirrorSyncRun.mirror_repo_id == mirror.id).all()
    )
    statuses = {r.status for r in remaining}
    assert statuses == {"ok", "failed", "running"}
    assert any(r.id == failed_row.id for r in remaining)
    assert any(r.id == running_row.id for r in remaining)


def test_retention_unlinks_manifest_file_when_present(db, tmp_path):
    mirror = _make_mirror(
        db,
        slug="test-ret-unlink",
        retention_keep_count=1,
        retention_keep_within_days=0,
    )
    db.commit()
    now = datetime.utcnow()

    # Two ok runs, oldest will be dropped; that row's manifest file
    # exists on disk and we expect it to be unlinked.
    old_manifest = tmp_path / "old.manifest.json"
    old_manifest.write_text('{"praxis_mirror_manifest":"v1"}')
    old_run = _add_ok_run(
        db,
        mirror,
        idx=1,
        finished_at=now - timedelta(days=10),
        manifest_path=old_manifest,
    )

    new_manifest = tmp_path / "new.manifest.json"
    new_manifest.write_text('{"praxis_mirror_manifest":"v1"}')
    _add_ok_run(
        db,
        mirror,
        idx=2,
        finished_at=now,
        manifest_path=new_manifest,
    )
    db.commit()

    assert old_manifest.exists() and new_manifest.exists()
    result = apply_retention_for_mirror(db, mirror, now=now)
    db.commit()

    assert old_run.id in result.dropped_run_ids
    assert result.manifest_files_unlinked == 1
    assert not old_manifest.exists()
    assert new_manifest.exists()  # newest kept


def test_retention_tolerates_already_missing_manifest_file(db, tmp_path):
    """If the manifest file vanished out from under us (operator
    cleanup, restored backup, etc.), retention should still drop the
    row — best-effort unlink with missing_ok=True.
    """
    mirror = _make_mirror(
        db,
        slug="test-ret-missing-file",
        retention_keep_count=1,
        retention_keep_within_days=0,
    )
    db.commit()
    now = datetime.utcnow()
    ghost = tmp_path / "ghost.manifest.json"  # never created
    old_run = _add_ok_run(
        db,
        mirror,
        idx=1,
        finished_at=now - timedelta(days=10),
        manifest_path=ghost,
    )
    _add_ok_run(db, mirror, idx=2, finished_at=now)
    db.commit()

    result = apply_retention_for_mirror(db, mirror, now=now)
    assert old_run.id in result.dropped_run_ids


def test_retention_isolated_per_mirror(db):
    """A mirror's retention should not touch sibling mirrors' rows."""
    target = _make_mirror(
        db,
        slug="test-ret-target",
        retention_keep_count=1,
        retention_keep_within_days=0,
    )
    sibling = _make_mirror(db, slug="test-ret-sibling")
    db.commit()
    now = datetime.utcnow()
    target_old = _add_ok_run(db, target, idx=1, finished_at=now - timedelta(days=10))
    target_new = _add_ok_run(db, target, idx=2, finished_at=now)
    sibling_old = _add_ok_run(db, sibling, idx=1, finished_at=now - timedelta(days=10))
    db.commit()

    result = apply_retention_for_mirror(db, target, now=now)

    assert target_old.id in result.dropped_run_ids
    assert sibling_old.id not in result.dropped_run_ids

    sibling_remaining = (
        db.query(MirrorSyncRun).filter(MirrorSyncRun.mirror_repo_id == sibling.id).all()
    )
    assert len(sibling_remaining) == 1


def test_retention_flushes_pending_ok_row_before_querying(db):
    """Production ``SessionLocal`` is autoflush=False. Without the
    explicit ``db.flush()`` inside ``apply_retention_for_mirror``,
    the just-finalized ok row sits in pending state and the
    retention query doesn't see it — so retention with keep_count=1
    would keep the *previous* ok row, leaving two manifests after
    the caller commits.

    P2 regression on 4a9a6c9. Wraps the call in
    ``db.no_autoflush`` to mirror prod semantics; the helper's own
    ``db.flush()`` must close the gap.
    """
    mirror = _make_mirror(
        db,
        slug="test-ret-flush-pending",
        retention_keep_count=1,
        retention_keep_within_days=0,
    )
    db.commit()

    now = datetime.utcnow()
    # Previous committed ok run — visible to the query without flush.
    previous = _add_ok_run(db, mirror, idx=1, finished_at=now - timedelta(hours=1))
    db.commit()

    # Pending ok run — added but not committed/flushed. Mimics the
    # state inside perform_sync_for_mirror after finalize-ok but
    # before the caller's commit.
    pending = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=now - timedelta(minutes=5),
        finished_at=now,
        status="ok",
        byte_count=42,
        package_count=1,
        manifest_sha256="0" * 64,
        manifest_path="/dev/null",
    )
    db.add(pending)

    with db.no_autoflush:
        result = apply_retention_for_mirror(db, mirror, now=now)
    db.commit()

    # The just-added pending row is the most recent ok row; keep_count=1
    # picks it. The previous (older) row should be dropped.
    assert previous.id in result.dropped_run_ids, (
        "previous ok row must be dropped — without retention's flush() the "
        "pending row would be invisible and the previous row would survive, "
        "leaving two ok manifests after the caller commits"
    )
    db.refresh(pending)
    assert pending.id is not None  # still there


def test_retention_uses_fresh_utcnow_when_caller_omits_now(db):
    """``now`` defaults to a fresh ``datetime.utcnow()`` when None —
    matches policy semantics ("within the last N days") better than
    the orchestrator's start-time ``now`` for long-running syncs.
    """
    mirror = _make_mirror(
        db,
        slug="test-ret-default-now",
        retention_keep_count=1,
        retention_keep_within_days=30,
    )
    db.commit()
    real_now = datetime.utcnow()
    # Old enough to be outside the 30-day window.
    old = _add_ok_run(db, mirror, idx=1, finished_at=real_now - timedelta(days=60))
    _add_ok_run(db, mirror, idx=2, finished_at=real_now)
    db.commit()

    # Caller doesn't pass now=. Helper computes a fresh utcnow().
    result = apply_retention_for_mirror(db, mirror)
    assert old.id in result.dropped_run_ids


def test_retention_minimum_policy_drops_all_but_most_recent(db):
    """With the most aggressive schema-allowed policy
    (``keep_count=1, keep_within_days=0``), only the newest ok row
    survives — count-of-1 picks it AND the floor backstops it as
    the same row.
    """
    mirror = _make_mirror(
        db,
        slug="test-ret-minimum-policy",
        retention_keep_count=1,
        retention_keep_within_days=0,
    )
    db.commit()
    now = datetime.utcnow()
    runs = [
        _add_ok_run(db, mirror, idx=i, finished_at=now - timedelta(days=4 - i))
        for i in range(1, 5)
    ]
    db.commit()

    result = apply_retention_for_mirror(db, mirror, now=now)
    # 4 ok runs, keep most recent (= runs[3], finished at now). Drop
    # the other 3.
    assert len(result.dropped_run_ids) == 3
    assert runs[3].id not in result.dropped_run_ids  # most recent kept


# ---------------------------------------------------------------------------
# PRA-158 #2-c: signature sidecar cleanup
# ---------------------------------------------------------------------------


def test_retention_unlinks_signature_sidecar_when_present(db, tmp_path):
    """Dropped signed runs must take their
    .manifest.json.sig sidecar with them, not just the manifest JSON.
    Without this, signed runs aging out leave orphan .sig files in
    snapshots/.
    """
    mirror = _make_mirror(
        db,
        slug="test-ret-sig-unlink",
        retention_keep_count=1,
        retention_keep_within_days=0,
    )
    db.commit()
    now = datetime.utcnow()

    old_manifest = tmp_path / "old.manifest.json"
    old_manifest.write_text('{"praxis_mirror_manifest":"v1"}')
    old_sig = tmp_path / "old.manifest.json.sig"
    old_sig.write_text("-----BEGIN PGP SIGNATURE-----\nfake\n-----END-----\n")

    old_run = _add_ok_run(
        db,
        mirror,
        idx=1,
        finished_at=now - timedelta(days=10),
        manifest_path=old_manifest,
        manifest_signature_path=old_sig,
    )

    new_manifest = tmp_path / "new.manifest.json"
    new_manifest.write_text('{"praxis_mirror_manifest":"v1"}')
    new_sig = tmp_path / "new.manifest.json.sig"
    new_sig.write_text("-----BEGIN PGP SIGNATURE-----\nfake\n-----END-----\n")
    _add_ok_run(
        db,
        mirror,
        idx=2,
        finished_at=now,
        manifest_path=new_manifest,
        manifest_signature_path=new_sig,
    )
    db.commit()

    assert old_sig.exists() and new_sig.exists()
    result = apply_retention_for_mirror(db, mirror, now=now)
    db.commit()

    assert old_run.id in result.dropped_run_ids
    assert result.manifest_files_unlinked == 1
    assert result.signature_files_unlinked == 1
    assert not old_sig.exists()
    assert new_sig.exists()  # newest kept


def test_retention_tolerates_missing_signature_sidecar(db, tmp_path):
    """If the .sig sidecar already vanished (operator cleanup, restore
    from backup, etc.), retention still drops the row — best-effort
    unlink with missing_ok mirrors the manifest behavior.
    """
    mirror = _make_mirror(
        db,
        slug="test-ret-sig-missing",
        retention_keep_count=1,
        retention_keep_within_days=0,
    )
    db.commit()
    now = datetime.utcnow()

    old_manifest = tmp_path / "old.manifest.json"
    old_manifest.write_text("{}")
    nonexistent_sig = tmp_path / "old.manifest.json.sig"
    # Note: we deliberately do NOT create nonexistent_sig.
    _add_ok_run(
        db,
        mirror,
        idx=1,
        finished_at=now - timedelta(days=10),
        manifest_path=old_manifest,
        manifest_signature_path=nonexistent_sig,
    )
    new_manifest = tmp_path / "new.manifest.json"
    new_manifest.write_text("{}")
    _add_ok_run(
        db,
        mirror,
        idx=2,
        finished_at=now,
        manifest_path=new_manifest,
    )
    db.commit()

    result = apply_retention_for_mirror(db, mirror, now=now)
    db.commit()
    # Counter convention matches the manifest counter: it tracks
    # *attempted* unlinks under missing_ok=True (one row had a
    # signature path, so the count is 1) — parallels the existing
    # ``manifest_files_unlinked`` semantics in
    # ``test_retention_tolerates_already_missing_manifest_file``.
    # The point of the test is the no-raise tolerance, not the count.
    assert result.signature_files_unlinked == 1
    assert len(result.dropped_run_ids) == 1


def test_retention_legacy_pra157_runs_have_no_signature_to_unlink(db, tmp_path):
    """Pre-PRA-158 ok runs have manifest_signature_path NULL. Retention
    drops their manifest, increments manifest_files_unlinked, and
    leaves signature_files_unlinked at zero.
    """
    mirror = _make_mirror(
        db,
        slug="test-ret-legacy",
        retention_keep_count=1,
        retention_keep_within_days=0,
    )
    db.commit()
    now = datetime.utcnow()

    old_manifest = tmp_path / "legacy-old.manifest.json"
    old_manifest.write_text("{}")
    _add_ok_run(
        db,
        mirror,
        idx=1,
        finished_at=now - timedelta(days=10),
        manifest_path=old_manifest,
        manifest_signature_path=None,
    )
    new_manifest = tmp_path / "legacy-new.manifest.json"
    new_manifest.write_text("{}")
    _add_ok_run(
        db,
        mirror,
        idx=2,
        finished_at=now,
        manifest_path=new_manifest,
        manifest_signature_path=None,
    )
    db.commit()

    result = apply_retention_for_mirror(db, mirror, now=now)
    db.commit()
    assert result.manifest_files_unlinked == 1
    assert result.signature_files_unlinked == 0
