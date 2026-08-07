"""PRA-160 slice #1: ``mirror_sync_runs.run_kind='import'`` is accepted
by the DB constraint AND the ORM ``__table_args__``.

Slice #3 will exercise this end-to-end via the importer; here we
just assert that:
  * The check constraint admits ``'import'`` (PRA-158 #2a admitted
    only ``sync | sign_only``; the slice #1 migration extends it).
  * The ORM mirror of ``__table_args__`` agrees so
    ``Base.metadata.create_all`` (used by some test fixtures) lays
    down the same schema.
  * Imported runs land as ``status='ok'`` directly. The test inserts
    a row with ``run_kind='import' status='ok'`` and asserts the
    PRA-157 service-level invariant (manifest fields non-null) holds.
"""

from __future__ import annotations

from datetime import datetime

from app.db.models import MirrorRepo, MirrorSyncRun


def _make_mirror(db) -> MirrorRepo:
    m = MirrorRepo(
        slug="ig-test",
        display_name="ig-test",
        package_family="deb",
        upstream_url="http://example.com",
        distribution="jammy",
        components="[]",
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
        source_mode="imported_offline",
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


def test_orm_table_args_admit_import(db):
    """ORM constraint mirrors the DB constraint."""
    constraints = MirrorSyncRun.__table_args__
    found = [
        c
        for c in constraints
        if getattr(c, "name", None) == "mirror_sync_runs_run_kind_valid"
    ]
    assert len(found) == 1
    sql = str(found[0].sqltext)
    assert "import" in sql
    assert "sync" in sql
    assert "sign_only" in sql


def test_imported_run_inserts_with_status_ok(db):
    mirror = _make_mirror(db)
    run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        status="ok",
        run_kind="import",
        byte_count=2048,
        package_count=4,
        manifest_sha256="a" * 64,
        manifest_path=f"/data/praxis/mirrors/{mirror.slug}/snapshots/imported.manifest.json",
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    assert run.id is not None
    assert run.status == "ok"
    assert run.run_kind == "import"
    # PRA-157 service-level invariant — manifest fields populated for
    # ``status='ok'`` regardless of run_kind.
    assert run.manifest_sha256 is not None
    assert run.manifest_path is not None
    assert run.byte_count is not None
    assert run.finished_at is not None
