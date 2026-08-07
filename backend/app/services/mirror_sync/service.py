"""Orchestrator that ties the per-mirror sync flow together
(PRA-157 #2a).

Called from the scheduler's ``_run_mirror_sync_due`` after the
claim path has acquired the per-mirror advisory lock and inserted
the ``mirror_sync_runs(status='running')`` row. The lock and run
row are this orchestrator's preconditions; it owns the sync flow
and the run-row finalization.

Flow per mirror::

    1. free-space gate (mirror_disk.check_free_space_gate)
       │   refuse → finalize 'failed' + return
       └── pass → proceed
    2. engine.sync(mirror, work_dir)
       │   ok=False → finalize 'failed' with error_text + return
       └── ok=True  → proceed
    3. rsync --delete work/ → live/  (promotion)
       │   rc != 0  → finalize 'failed' with error_text + return
       └── rc == 0 → proceed
    4. build manifest from live/, write manifest JSON
    5. finalize run row as 'ok' with manifest fields + update
       mirror_repos state (last_sync_finished_at, current_disk_bytes,
       last_sync_status='ok')

All DB writes happen inside short Sessions provided by the caller.
The orchestrator does not commit — caller orchestrates transaction
boundaries.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from .. import mirror_gpg
from ..mirror_disk import check_free_space_gate
from ..mirror_manifest import build_manifest, manifest_sha256
from ..mirror_paths import last_error_path, live_dir, mirror_repo_root, work_dir
from ..mirror_signing import engine_for as signing_engine_for
from ..mirror_signing.manifest import (
    cleanup_staged,
    promote_staged_manifest,
    stage_signed_manifest,
)
from ..mirror_signing_key_service import MirrorSigningKeyService
from . import engine_for

logger = logging.getLogger(__name__)

# Promotion subprocess timeout. rsync over a multi-GB tree can take
# minutes; cap at 1h to bound runaway promotion without breaking
# legitimate large mirrors. Tunable later if needed.
RSYNC_TIMEOUT_SECONDS = 60 * 60

# Bytes of rsync stderr/stdout captured into error_text on failure.
ERROR_TAIL_BYTES = 8 * 1024


def perform_sync_for_mirror(
    db,
    mirror,  # noqa: ANN001
    run,  # noqa: ANN001
    *,
    prior_status: Optional[str] = None,
    now: Optional[datetime] = None,
) -> "Tuple[bool, List[mirror_alerts.MirrorAlertEvent]]":
    """Run the full sync flow for one mirror.

    ``mirror`` and ``run`` are loaded ORM rows; the caller is
    responsible for the per-mirror advisory lock + having inserted
    the ``running`` run row + flushing.

    ``prior_status`` is the mirror's ``last_sync_status`` BEFORE the
    claim path mutated it to 'running'. The caller (``mirror_sweep
    .claim_and_sync_one_mirror``) captures it inside
    ``_persist_claim_for_mirror`` and threads it through. Used only
    for the recovery-alert transition gate (failed→ok). When unset,
    no recovery alert is built.

    Returns ``(ok, events)`` where:
      * ``ok`` is True iff the run finalized as 'ok'.
      * ``events`` is the list of ``MirrorAlertEvent`` records the
        caller should fire on a fresh, non-sync session via
        ``mirror_alerts.dispatch_alert_events``.

    The orchestrator does NOT touch the alert path — that's the
    PRA-157 #2b-a fix for the alert/sync transaction-coupling P2.
    Caller commits sync state on this session, then opens a fresh
    session for alert dispatch.
    """
    from .. import mirror_alerts

    now = now or datetime.utcnow()
    slug = mirror.slug

    events: "List[mirror_alerts.MirrorAlertEvent]" = []

    mirror_repo_root(slug).mkdir(parents=True, exist_ok=True)
    work = work_dir(slug)
    live = live_dir(slug)

    engine = engine_for(mirror)

    # ---- (1) free-space gate ------------------------------------------------
    estimate = engine.estimate_sync_bytes(mirror)
    decision = check_free_space_gate(
        estimate_bytes=estimate,
        mirror_disk_budget=mirror.disk_budget_bytes,
        current_disk_bytes=mirror.current_disk_bytes or 0,
    )
    run.estimate_unavailable = decision.estimate_unavailable

    if not decision.allowed:
        _finalize_failed(
            db,
            mirror,
            run,
            now,
            error_text=f"free-space gate refused: {decision.reason}",
        )
        events.append(mirror_alerts.build_disk_pressure_event(mirror, decision.reason))
        return False, events

    # ---- (2) engine subprocess ---------------------------------------------
    sync_result = engine.sync(mirror, work)
    if not sync_result.ok:
        err = sync_result.error_text or "engine sync failed"
        _finalize_failed(db, mirror, run, now, error_text=err)
        events.append(mirror_alerts.build_sync_failed_event(mirror, err))
        return False, events

    # ---- (2.5) PRA-158 #4b: pre-sign upstream-verify gate ------------------
    # Verifies upstream Release.gpg/InRelease/repomd.xml.asc against a
    # transient keyring built from mirror_upstream_keys. Only fires
    # for upstream_sync mirrors with verify_upstream_signature=true;
    # imported_offline mirrors and operators who haven't opted in
    # skip cleanly. Failure aborts the sync, fires the
    # mirror_upstream_signature_invalid alert, and leaves live/
    # untouched (PRA-157 invariant preserved).
    if mirror.verify_upstream_signature and mirror.source_mode == "upstream_sync":
        from .. import mirror_upstream_verify

        verify = mirror_upstream_verify.verify_upstream_signatures(db, mirror, work)
        if not verify.ok:
            err = f"upstream signature invalid: {verify.error_text}"
            _finalize_failed(db, mirror, run, now, error_text=err)
            events.append(
                mirror_alerts.build_upstream_invalid_event(
                    mirror, verify.error_text or "verification failed"
                )
            )
            return False, events

    # ---- (3) PRA-158 fence: native sign + manifest sign in work/ -----------
    # Fence ordering (project_pra158_design_locks.md): everything is
    # signed in work/ + staged in snapshots-staging/<run_id>/ BEFORE
    # rsync work/ → live/. On any failure between here and the rsync,
    # cleanup_staged drops the per-run staging dir and live/ is
    # untouched (PRA-157 invariant preserved).
    try:
        sign_outcome = _sign_run_in_work(db, mirror, run, work)
    except Exception as exc:  # pylint: disable=broad-except
        cleanup_staged(slug, run.id)
        err = f"signing pipeline crashed: {exc}"
        _finalize_failed(db, mirror, run, now, error_text=err)
        events.append(mirror_alerts.build_sync_failed_event(mirror, err))
        return False, events

    if not sign_outcome.ok:
        cleanup_staged(slug, run.id)
        err = sign_outcome.error_text or "signing failed"
        _finalize_failed(db, mirror, run, now, error_text=err)
        events.append(mirror_alerts.build_sync_failed_event(mirror, err))
        return False, events

    # ---- (4) work/ → live/ promotion via rsync --delete --------------------
    promote_result = _promote_work_to_live(work, live)
    if not promote_result.ok:
        cleanup_staged(slug, run.id)
        err = promote_result.error_text or "promotion failed"
        _finalize_failed(db, mirror, run, now, error_text=err)
        events.append(mirror_alerts.build_sync_failed_event(mirror, err))
        return False, events

    # ---- (5) promote staged manifest+sig into snapshots/ -------------------
    try:
        manifest_path, sig_path = promote_staged_manifest(slug, run.id)
    except (FileNotFoundError, OSError) as exc:
        # rsync succeeded but the staged sidecar promote failed. live/
        # has new content; the manifest is missing. Mark failed; an
        # operator can re-sync to re-stage + re-promote (next run will
        # also re-sign live/).
        err = f"manifest promote failed post-rsync: {exc}"
        _finalize_failed(db, mirror, run, now, error_text=err)
        events.append(mirror_alerts.build_sync_failed_event(mirror, err))
        return False, events

    # ---- (6) finalize ok ---------------------------------------------------
    run.status = "ok"
    run.finished_at = now
    run.byte_count = sign_outcome.manifest_byte_count
    run.package_count = sign_outcome.manifest_package_count
    run.manifest_sha256 = sign_outcome.manifest_sha256
    run.manifest_path = str(manifest_path)
    run.manifest_signature_path = str(sig_path)
    run.signed_with_key_id = sign_outcome.signed_with_key_id
    run.error_text = None

    # PRA-164 slice 3: derived per-package index for the preflight
    # availability resolver. Reads the manifest file once, writes one
    # row per parsed package entry into mirror_sync_run_packages. Use
    # the safe wrapper so an index failure never breaks the parent
    # sync transaction — the backfill helper retries on first preflight.
    from .. import mirror_package_index  # local import: avoid cycles

    mirror_package_index.populate_from_run_safe(db, run)

    mirror.last_sync_finished_at = now
    mirror.last_sync_status = "ok"
    mirror.last_sync_error = None
    mirror.current_disk_bytes = run.byte_count

    # Clear any prior on-disk error breadcrumb so an operator looking
    # at .last-error in the volume sees a fresh state.
    try:
        last_error_path(slug).unlink(missing_ok=True)
    except OSError as exc:  # pragma: no cover - belt
        logger.warning("couldn't unlink .last-error for %s: %s", slug, exc)

    # Recovery alert: gated on the failed → ok transition. The
    # caller's prior_status capture happens before the claim path
    # mutates last_sync_status to 'running', so this still reflects
    # the *previous completed* status, not 'running'.
    if prior_status == "failed":
        events.append(mirror_alerts.build_sync_completed_event(mirror))

    # PRA-157 #4: post-success retention. Drops ok run rows + their
    # manifest JSON files outside the retention window. Bytes in
    # live/work/ are NOT touched — PRA-159 owns byte-level
    # immutability when channels need it. Runs in the same session
    # so finalization and retention commit atomically (caller
    # commits after this function returns).
    #
    # Retention uses a fresh ``utcnow()`` — its "within the last N
    # days" policy is best served by real-clock time rather than the
    # orchestrator's start-time ``now`` (which can be hours stale
    # after a long sync).
    #
    # No outer try/except: unlink errors are already swallowed
    # inside retention (orphaned files surface via logs); a DB /
    # session error here SHOULD bubble so the caller's belt-finalize
    # rolls back rather than pretending the sync was clean.
    from ..mirror_retention import apply_retention_for_mirror

    apply_retention_for_mirror(db, mirror)

    return True, events


class _SignOutcome:
    """Output of ``_sign_run_in_work``.

    Carries the manifest stats so the caller (orchestrator step #6)
    can finalize the run row without re-walking the tree.
    """

    __slots__ = (
        "ok",
        "error_text",
        "manifest_byte_count",
        "manifest_package_count",
        "manifest_sha256",
        "signed_with_key_id",
    )

    def __init__(
        self,
        *,
        ok: bool,
        error_text: Optional[str] = None,
        manifest_byte_count: int = 0,
        manifest_package_count: int = 0,
        manifest_sha256_hex: Optional[str] = None,
        signed_with_key_id: Optional[int] = None,
    ):
        self.ok = ok
        self.error_text = error_text
        self.manifest_byte_count = manifest_byte_count
        self.manifest_package_count = manifest_package_count
        self.manifest_sha256 = manifest_sha256_hex
        self.signed_with_key_id = signed_with_key_id


def _sign_run_in_work(db, mirror, run, work: Path) -> _SignOutcome:  # noqa: ANN001
    """Native-sign work/ + build/sign manifest into snapshots-staging/.

    PRA-158 #2c fence step. Sequence:
      1. ``MirrorSigningKeyService.ensure_active`` — generates a key on
         first sync; idempotent under the per-mirror advisory lock.
      2. Open ephemeral GNUPGHOME, import private key from Vault, verify
         fingerprint matches the DB row (mirror_gpg's
         ``import_and_verify`` raises on mismatch).
      3. Native sign in work/ via the package-family signing engine.
      4. Build manifest from work/ (the already-signed tree).
      5. Sign manifest → snapshots-staging/<run_id>/manifest.json{,.sig}.

    On success, the caller proceeds to rsync work/ → live/ then promotes
    the staged sidecar. On failure, the caller calls ``cleanup_staged``
    and finalizes the run as failed; live/ is never touched.

    Vault read failures (no public_armored, missing private_armored,
    fingerprint mismatch) raise rather than being squashed into a
    SigningResult — they're a deeper integrity problem than a signing
    engine failure and the orchestrator's outer try/except handles them
    via the cleanup_staged + failed-finalize path.
    """
    slug = mirror.slug

    key_service = MirrorSigningKeyService(db)
    key = key_service.ensure_active(mirror)

    secret = key_service.vault.read_secret(key.vault_path)
    if not secret or "private_armored" not in secret:
        return _SignOutcome(
            ok=False,
            error_text=(
                f"signing key {key.gpg_fingerprint} has no private_armored "
                f"in vault at {key.vault_path}"
            ),
        )
    private_armored = secret["private_armored"]

    with mirror_gpg.ephemeral_gnupg_home() as home:
        try:
            mirror_gpg.import_and_verify(home, private_armored, key.gpg_fingerprint)
        except mirror_gpg.MirrorGPGError as exc:
            return _SignOutcome(ok=False, error_text=f"key import: {exc}")

        # Native signing — InRelease + Release.gpg for deb;
        # repomd.xml.asc + repomd.xml.key for rpm.
        sig_engine = signing_engine_for(mirror)
        native_result = sig_engine.sign_native(work, key.gpg_fingerprint, home)
        if not native_result.ok:
            return _SignOutcome(
                ok=False,
                error_text=native_result.error_text or "native signing failed",
            )

        # Build manifest from the now-signed work/ tree.
        try:
            manifest = build_manifest(
                slug=slug,
                run_id=run.id,
                package_family=mirror.package_family,
                root=work,
            )
        except OSError as exc:
            return _SignOutcome(ok=False, error_text=f"manifest build: {exc}")

        sha = manifest_sha256(manifest)

        # Sign + stage — the caller's promote step moves the sidecar
        # into snapshots/ after rsync succeeds.
        try:
            stage_signed_manifest(
                slug=slug,
                run_id=run.id,
                manifest=manifest,
                key_fingerprint=key.gpg_fingerprint,
                gnupg_home=home,
            )
        except (mirror_gpg.MirrorGPGError, OSError) as exc:
            return _SignOutcome(ok=False, error_text=f"manifest sign/stage: {exc}")

    return _SignOutcome(
        ok=True,
        manifest_byte_count=manifest.get("byte_count", 0),
        manifest_package_count=manifest.get("package_count", 0),
        manifest_sha256_hex=sha,
        signed_with_key_id=key.id,
    )


def _finalize_failed(
    db,
    mirror,  # noqa: ANN001
    run,  # noqa: ANN001
    now: datetime,
    *,
    error_text: str,
) -> None:
    run.status = "failed"
    run.finished_at = now
    run.error_text = error_text

    mirror.last_sync_finished_at = now
    mirror.last_sync_status = "failed"
    mirror.last_sync_error = error_text

    try:
        path = last_error_path(mirror.slug)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(error_text)
    except OSError as exc:  # pragma: no cover - belt
        logger.warning("couldn't write .last-error for %s: %s", mirror.slug, exc)


class _PromoteResult:
    __slots__ = ("ok", "error_text")

    def __init__(self, ok: bool, error_text: Optional[str] = None):
        self.ok = ok
        self.error_text = error_text


def _promote_work_to_live(work: Path, live: Path) -> _PromoteResult:
    """``rsync --delete work/ live/`` promotion.

    Trailing slashes matter: ``rsync work/ live/`` copies the
    contents of work into live (not the work directory itself).
    ``--delete`` ensures live mirrors work exactly — files removed
    upstream are removed locally.

    Falls back to a copy-then-replace if rsync is missing (shouldn't
    happen in our containers, but a deploying operator who removes
    rsync from the image deserves a clear error rather than a
    crash).
    """
    if not work.exists():
        return _PromoteResult(ok=False, error_text=f"work dir {work} missing post-sync")
    live.mkdir(parents=True, exist_ok=True)

    if shutil.which("rsync") is None:
        return _PromoteResult(
            ok=False,
            error_text=(
                "rsync not found on PATH — Dockerfile must install "
                "the 'rsync' package"
            ),
        )

    argv = [
        "rsync",
        "-a",  # archive: preserve perms, times, links, ownership
        "--delete",  # remove from live what's no longer in work
        f"{str(work).rstrip('/')}/",  # trailing slash = contents-of
        f"{str(live).rstrip('/')}/",
    ]
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=RSYNC_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _PromoteResult(
            ok=False,
            error_text=(f"rsync promotion exceeded {RSYNC_TIMEOUT_SECONDS}s timeout"),
        )

    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or b"")[-ERROR_TAIL_BYTES:]
        return _PromoteResult(
            ok=False,
            error_text=(
                f"rsync exited rc={proc.returncode}; "
                f"tail: {tail.decode('utf-8', errors='replace')}"
            ),
        )
    return _PromoteResult(ok=True)
