"""sign-current — retrofit signatures onto a mirror's current live/ tree
(PRA-158 #2c).

Distinct from the sync orchestrator (``mirror_sync.service``) because:

  * It does NOT pull from upstream — works for ``imported_offline``
    mirrors which refuse on-demand sync per PRA-157.
  * It signs ``live/`` directly (not work/ → staging → promote) because
    live/ is already the published, coherent tree. No promotion step
    means no fence-ordered staging; per-file ``_atomic_write_bytes``
    in the engines preserves concurrent-reader safety.
  * It writes a ``run_kind='sign_only'`` row so sync history can
    distinguish retrofit runs from real syncs.

Use cases:
  * Pre-PRA-158 mirrors with unsigned live/ trees that need backfill.
  * ``imported_offline`` mirrors imported from elsewhere.
  * Operator-initiated re-sign after a key rotation cutover when
    waiting for the next scheduled sync isn't desired.

Locked for PRA-160: the importer signs imported content using this
same ``perform_sign_current_for_mirror`` primitive at import time.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from . import mirror_gpg
from .mirror_manifest import build_manifest, manifest_sha256
from .mirror_paths import last_error_path, live_dir
from .mirror_signing import engine_for as signing_engine_for
from .mirror_signing.manifest import (
    cleanup_staged,
    promote_staged_manifest,
    stage_signed_manifest,
)
from .mirror_signing_key_service import MirrorSigningKeyService

logger = logging.getLogger(__name__)


class SignCurrentResult:
    """Outcome of a sign-current run.

    ``ok`` mirrors the orchestrator pattern. ``run_id`` is the new
    sign_only row's id (or None if the run row never landed).
    """

    __slots__ = ("ok", "error_text", "run_id")

    def __init__(
        self,
        *,
        ok: bool,
        run_id: Optional[int] = None,
        error_text: Optional[str] = None,
    ):
        self.ok = ok
        self.run_id = run_id
        self.error_text = error_text


def perform_sign_current_for_mirror(db, mirror) -> SignCurrentResult:  # noqa: ANN001
    """Sign whatever is currently in ``live/`` and record a sign_only run.

    Caller must hold the per-mirror advisory lock (use
    ``mirror_lock.claim_mirror_for_sync`` — same lock as sync so the
    two paths can't race). The caller is also responsible for inserting
    the running ``mirror_sync_runs`` row and committing it before
    calling this function; finalization happens in-place on the row.

    Returns a ``SignCurrentResult``. The caller commits the session
    after this returns. **No alert events are fired in this slice** —
    sign-current is operator-initiated and the failed run row is
    visible immediately in the UI; alert plumbing is deferred (see
    ``project_pra158_design_locks.md`` "deferred for slice #2"). When
    a future slice wires alerts, they should dispatch on a fresh
    session per the PRA-157 #2b-a transaction-decoupling rule.
    """
    from .mirror_sync.service import _finalize_failed  # avoid circular at import

    now = datetime.utcnow()
    slug = mirror.slug
    live = live_dir(slug)

    # Look up the in-progress sign_only run row the caller inserted
    # — by convention it's the most recent running sign_only row for
    # this mirror.
    from ..db.models import MirrorSyncRun

    run = (
        db.query(MirrorSyncRun)
        .filter(
            MirrorSyncRun.mirror_repo_id == mirror.id,
            MirrorSyncRun.run_kind == "sign_only",
            MirrorSyncRun.status == "running",
        )
        .order_by(MirrorSyncRun.started_at.desc())
        .first()
    )
    if run is None:
        return SignCurrentResult(
            ok=False,
            error_text="sign_only run row not found — caller must insert before invoking",
        )

    if not live.exists() or not any(live.iterdir()):
        _finalize_failed(
            db,
            mirror,
            run,
            now,
            error_text=(
                f"live/ for mirror {slug!r} is empty or missing — nothing to sign. "
                "Run a real sync first or import content."
            ),
        )
        return SignCurrentResult(ok=False, run_id=run.id, error_text="live/ empty")

    key_service = MirrorSigningKeyService(db)
    key = key_service.ensure_active(mirror)

    secret = key_service.vault.read_secret(key.vault_path)
    if not secret or "private_armored" not in secret:
        err = (
            f"signing key {key.gpg_fingerprint} has no private_armored "
            f"in vault at {key.vault_path}"
        )
        _finalize_failed(db, mirror, run, now, error_text=err)
        return SignCurrentResult(ok=False, run_id=run.id, error_text=err)
    private_armored = secret["private_armored"]

    with mirror_gpg.ephemeral_gnupg_home() as home:
        try:
            mirror_gpg.import_and_verify(home, private_armored, key.gpg_fingerprint)
        except mirror_gpg.MirrorGPGError as exc:
            err = f"key import: {exc}"
            _finalize_failed(db, mirror, run, now, error_text=err)
            return SignCurrentResult(ok=False, run_id=run.id, error_text=err)

        sig_engine = signing_engine_for(mirror)
        native_result = sig_engine.sign_native(live, key.gpg_fingerprint, home)
        if not native_result.ok:
            err = native_result.error_text or "native signing failed"
            _finalize_failed(db, mirror, run, now, error_text=err)
            return SignCurrentResult(ok=False, run_id=run.id, error_text=err)

        try:
            manifest = build_manifest(
                slug=slug,
                run_id=run.id,
                package_family=mirror.package_family,
                root=live,
            )
        except OSError as exc:
            err = f"manifest build: {exc}"
            _finalize_failed(db, mirror, run, now, error_text=err)
            return SignCurrentResult(ok=False, run_id=run.id, error_text=err)

        sha = manifest_sha256(manifest)

        # Stage manifest + signature as a pair, then promote atomically.
        # Direct snapshots/ writes risked leaving an unsigned manifest
        # behind if the sig write failed
        # mid-flight. Reuses the same stage/promote primitives the sync
        # path uses; native sign of live/ above stays direct
        # (acceptable for v1 because sig artifacts are NEW files,
        # per-file atomic rename, no paired-publish contract on the
        # native side).
        try:
            stage_signed_manifest(
                slug=slug,
                run_id=run.id,
                manifest=manifest,
                key_fingerprint=key.gpg_fingerprint,
                gnupg_home=home,
            )
        except (mirror_gpg.MirrorGPGError, OSError) as exc:
            cleanup_staged(slug, run.id)
            err = f"manifest sign/stage: {exc}"
            _finalize_failed(db, mirror, run, now, error_text=err)
            return SignCurrentResult(ok=False, run_id=run.id, error_text=err)

    # Promote: mv staged manifest+sig into snapshots/ as an
    # all-or-nothing pair. promote_staged_manifest rolls back the
    # manifest mv on sig-mv failure (#2-a fix).
    try:
        manifest_path, sig_path = promote_staged_manifest(slug, run.id)
    except (FileNotFoundError, OSError) as exc:
        cleanup_staged(slug, run.id)
        err = f"manifest/sig promote: {exc}"
        _finalize_failed(db, mirror, run, now, error_text=err)
        return SignCurrentResult(ok=False, run_id=run.id, error_text=err)

    # Finalize ok — sign_only does NOT mutate mirror.last_sync_status
    # (that's reserved for full syncs, per the PRA-157 mirror-state
    # semantics). It only updates the run row.
    run.status = "ok"
    run.finished_at = now
    run.byte_count = manifest.get("byte_count", 0)
    run.package_count = manifest.get("package_count", 0)
    run.manifest_sha256 = sha
    run.manifest_path = str(manifest_path)
    run.manifest_signature_path = str(sig_path)
    run.signed_with_key_id = key.id
    run.error_text = None

    try:
        last_error_path(slug).unlink(missing_ok=True)
    except OSError as exc:  # pragma: no cover - belt
        logger.warning("couldn't unlink .last-error for %s: %s", slug, exc)

    logger.info(
        "sign-current ok for slug=%s run_id=%s key=%s",
        slug,
        run.id,
        key.gpg_fingerprint,
    )
    return SignCurrentResult(ok=True, run_id=run.id)


def claim_and_sign_current(mirror_id: int, slug: str) -> str:
    """Per-mirror lock + run-row insert + sign-current dispatch (PRA-158 #2c).

    Returns one of:
      * ``"locked"`` — another worker is syncing or signing this mirror.
      * ``"vanished"`` — mirror disappeared between enqueue and dispatch.
      * ``"ok"`` — sign_only run finalized as status=ok.
      * ``"failed"`` — sign_only run finalized as status=failed.
    """
    from ..db.models import MirrorRepo, MirrorSyncRun
    from ..db.session import SessionLocal
    from .mirror_lock import claim_mirror_for_sync

    with claim_mirror_for_sync(mirror_id) as acquired:
        if not acquired:
            return "locked"

        run_id: Optional[int] = None
        insert_db = SessionLocal()
        try:
            mirror = (
                insert_db.query(MirrorRepo)
                .filter(MirrorRepo.id == mirror_id, MirrorRepo.deleted_at.is_(None))
                .first()
            )
            if mirror is None:
                return "vanished"
            run = MirrorSyncRun(
                mirror_repo_id=mirror_id,
                started_at=datetime.utcnow(),
                status="running",
                run_kind="sign_only",
            )
            insert_db.add(run)
            insert_db.commit()
            run_id = run.id
        finally:
            insert_db.close()

        sign_db = SessionLocal()
        try:
            mirror = (
                sign_db.query(MirrorRepo).filter(MirrorRepo.id == mirror_id).first()
            )
            if mirror is None:
                return "vanished"
            try:
                result = perform_sign_current_for_mirror(sign_db, mirror)
                sign_db.commit()
                return "ok" if result.ok else "failed"
            except Exception as exc:  # pylint: disable=broad-except
                sign_db.rollback()
                logger.exception(
                    "sign-current: unexpected error for slug=%s: %s", slug, exc
                )
                # Belt-finalize the run row in a fresh session.
                if run_id is not None:
                    cleanup_db = SessionLocal()
                    try:
                        run = (
                            cleanup_db.query(MirrorSyncRun)
                            .filter(MirrorSyncRun.id == run_id)
                            .first()
                        )
                        if run is not None and run.status == "running":
                            run.status = "failed"
                            run.finished_at = datetime.utcnow()
                            run.error_text = f"sign-current crashed: {exc}"
                            cleanup_db.commit()
                    finally:
                        cleanup_db.close()
                return "failed"
        finally:
            sign_db.close()
