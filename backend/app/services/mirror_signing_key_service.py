"""Per-mirror signing key lifecycle (PRA-158 slice #1).

Slice #1 ships:
  * ``ensure_active(mirror)`` — lazy creation on first call; idempotent.
  * ``get_active(mirror_id)`` — returns the current active key or ``None``.
  * ``get_public_armored(key)`` — fetches the public half from Vault.
  * ``list_for_mirror(mirror_id, include_retired=False)`` — admin/UI read.
  * ``bundle_public_keys(mirror_id)`` — active + pending_cutover +
    rotating_out (NEVER retired) for the trust-bundle endpoint that
    slice #3 builds on.

Locks (project_pra158_design_locks.md):
  * Per-mirror keys, not Praxis-wide.
  * Lazy generation lives inside this service; the existing per-mirror
    sync advisory lock ``(0x4D52, mirror_id)`` covers the race when
    triggered from a sync (slice #2 wires that). Standalone calls from
    the bootstrap endpoint accept a small "two creators race" window —
    the Vault write is idempotent and the second loser will see the
    first row on retry.
  * Vault path: ``praxis/mirror-signing-keys/<mirror_slug>/<fingerprint>``.
  * Vault payload: ``{"private_armored": ..., "public_armored": ...}``.
    Public is duplicated into Vault so a single read covers everything
    callers need without a second round-trip; it's not a secret either
    way.
  * Generation runs under an ephemeral GNUPGHOME (see ``mirror_gpg``);
    the home is wiped before this method returns.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..db.models import HostMirrorTrust, MirrorRepo, MirrorSigningKey, System
from . import mirror_gpg
from .vault_service import VaultService

logger = logging.getLogger(__name__)


class RotationError(RuntimeError):
    """Raised on illegal rotation transitions (PRA-158 #5a).

    Distinct exception type so route handlers can map to 409 Conflict
    without conflating with deeper IntegrityError paths.
    """


class RotationNotFound(RotationError):
    """Raised when a key id is unknown OR belongs to a different mirror
    (PRA-158 #5-b).

    Route handlers map this specifically to 404. The wording does not
    distinguish "unknown id" from "cross-mirror id" so callers can't
    probe whether a key exists for a different mirror — non-leakage
    is the locked behavior. Subclass of ``RotationError`` so callers
    that catch the parent still see these.
    """


class CutoverBlocked(RuntimeError):
    """Raised when ``cutover(force=False)`` would leave hosts without
    the pending key (PRA-158 #5a).

    ``preview`` carries the structured host buckets so the route
    handler can surface them in the 409 body without re-running the
    preview query.
    """

    def __init__(self, preview: dict):
        super().__init__("cutover blocked: hosts are not yet trusting the pending key")
        self.preview = preview


VAULT_PATH_PREFIX = "praxis/mirror-signing-keys"


def vault_path_for(slug: str, fingerprint: str) -> str:
    """Compose the Vault KV path for a (slug, fingerprint) pair.

    Centralised so the schema doesn't drift between writers and readers.
    Both inputs are constrained — slug is validated upstream by
    ``schemas.mirrors._validate_slug``; fingerprint is 40 hex chars from
    GPG. Neither contains path-traversal characters.
    """
    return f"{VAULT_PATH_PREFIX}/{slug}/{fingerprint}"


class MirrorSigningKeyService:
    """Manage per-mirror signing keys (PRA-158)."""

    def __init__(self, db: Session, vault: Optional[VaultService] = None):
        self.db = db
        # Vault is injectable for tests (``mock_vault`` in conftest);
        # production callers pass ``VaultService(db)``.
        self.vault = vault if vault is not None else VaultService(db)

    # ------------------------------------------------------------------
    # Read paths
    # ------------------------------------------------------------------

    def get_active(self, mirror_id: int) -> Optional[MirrorSigningKey]:
        """Return the current active key for a mirror, or ``None``."""
        return (
            self.db.query(MirrorSigningKey)
            .filter(
                MirrorSigningKey.mirror_repo_id == mirror_id,
                MirrorSigningKey.status == "active",
            )
            .one_or_none()
        )

    def list_for_mirror(
        self, mirror_id: int, include_retired: bool = False
    ) -> List[MirrorSigningKey]:
        """Return all keys for a mirror, newest first.

        Excludes ``retired`` by default so the common UI/API surface
        doesn't drown in historical rows; admin tools can pass
        ``include_retired=True`` for audit views.
        """
        query = self.db.query(MirrorSigningKey).filter(
            MirrorSigningKey.mirror_repo_id == mirror_id
        )
        if not include_retired:
            query = query.filter(MirrorSigningKey.status != "retired")
        return query.order_by(MirrorSigningKey.created_at.desc()).all()

    def bundle_public_keys(self, mirror_id: int) -> List[MirrorSigningKey]:
        """Return the trust-bundle set: active + pending_cutover + rotating_out.

        Slice #3 builds the public-key endpoint on top of this. Order
        is deterministic (active first, then pending_cutover, then
        rotating_out by created_at desc) so installers can rely on
        "the first key is the one that's signing right now" without
        having to sort client-side.

        Locked invariant: ``retired`` keys are NEVER in the bundle.
        """
        rows = (
            self.db.query(MirrorSigningKey)
            .filter(
                MirrorSigningKey.mirror_repo_id == mirror_id,
                MirrorSigningKey.status.in_(
                    ("active", "pending_cutover", "rotating_out")
                ),
            )
            .all()
        )
        order = {"active": 0, "pending_cutover": 1, "rotating_out": 2}
        return sorted(
            rows,
            key=lambda r: (order.get(r.status, 99), -int(r.created_at.timestamp())),
        )

    def get_public_armored(self, key: MirrorSigningKey) -> str:
        """Return the armored public key for ``key``.

        PRA-158 #3a: public
        material is cached on the ``armored_public_key`` column so
        trust-bundle reads (slice #3b) don't pull private material
        from Vault on every fetch.

        For pre-#3a slice #1 rows the column is NULL; backfill lazily
        from Vault on first read and persist. Vault remains the source
        of truth for the private half (and the historical public copy
        is kept there too for round-trip integrity), but the column
        becomes the hot read path.

        Raises ``RuntimeError`` if both DB and Vault are empty — that
        means the row was created but the secret never landed, which
        should never happen and is worth surfacing loudly.
        """
        if key.armored_public_key:
            return key.armored_public_key

        # Lazy backfill path for slice #1 rows. Reads private+public
        # from Vault, keeps only public, writes back to the DB column
        # so subsequent reads are DB-only.
        secret = self.vault.read_secret(key.vault_path)
        if not secret or "public_armored" not in secret:
            raise RuntimeError(
                f"signing key {key.gpg_fingerprint} has no public material "
                f"in DB or vault at {key.vault_path}"
            )
        public = secret["public_armored"]
        key.armored_public_key = public
        self.db.add(key)
        self.db.commit()
        self.db.refresh(key)
        return public

    # ------------------------------------------------------------------
    # Write paths
    # ------------------------------------------------------------------

    def ensure_active(self, mirror: MirrorRepo) -> MirrorSigningKey:
        """Return the mirror's active signing key, generating if absent.

        Idempotent: callers can invoke this on every sync without
        worrying about duplicate rows. Generation does an ephemeral
        GNUPGHOME → gpg --gen-key → export private+public → Vault
        write → DB row insert sequence. The GNUPGHOME is wiped before
        this method returns regardless of success/failure.

        Concurrent-bootstrap safety (slice #1-a): the partial unique
        index ``uq_mirror_signing_keys_one_active_per_mirror`` enforces
        at most one ``active`` row per mirror. If two callers race past
        the existence check, the second insert hits IntegrityError; the
        loser cleans up its orphan Vault entry, re-fetches the winner,
        and returns it. Slice #2 will additionally hold the per-mirror
        sync advisory lock around this call so the race window in the
        sync path is fully closed; the bootstrap endpoint relies on the
        DB constraint alone, which is sufficient.
        """
        existing = self.get_active(mirror.id)
        if existing is not None:
            return existing

        # Generate inside an ephemeral home, wipe on exit.
        with mirror_gpg.ephemeral_gnupg_home() as home:
            fingerprint = mirror_gpg.generate_keypair(home, mirror.slug)
            private_armored = mirror_gpg.export_secret_armored(home, fingerprint)
            public_armored = mirror_gpg.export_public_armored(home, fingerprint)

        vault_path = vault_path_for(mirror.slug, fingerprint)
        wrote = self.vault.write_secret(
            vault_path,
            {
                "private_armored": private_armored,
                "public_armored": public_armored,
            },
        )
        if not wrote:
            raise RuntimeError(
                f"Vault write failed for mirror signing key at {vault_path}"
            )

        key_uid = f"Praxis Mirror Signing {mirror.slug} {fingerprint}"
        row = MirrorSigningKey(
            mirror_repo_id=mirror.id,
            status="active",
            gpg_fingerprint=fingerprint,
            key_uid=key_uid,
            vault_path=vault_path,
            # PRA-158 #3a: cache the public half on the row at
            # generation time so trust-bundle reads stay off the
            # Vault path. Vault still holds the canonical private +
            # historical public.
            armored_public_key=public_armored,
        )
        self.db.add(row)
        try:
            self.db.commit()
        except IntegrityError:
            # Concurrent bootstrap won the race. Drop our orphan Vault
            # entry (we hold the only reference to its fingerprint —
            # the winner's row points at a different one) and return
            # the winner. Vault delete failures are logged but do not
            # mask the original race resolution: the orphan is reachable
            # by fingerprint via the path log line below if cleanup is
            # ever needed.
            self.db.rollback()
            try:
                self.vault.delete_secret(vault_path)
            except Exception as cleanup_err:  # pylint: disable=broad-except
                logger.warning(
                    "Failed to clean up orphan vault entry at %s after "
                    "bootstrap race: %s",
                    vault_path,
                    cleanup_err,
                )
            winner = self.get_active(mirror.id)
            if winner is None:
                # Should never happen: the IntegrityError says someone
                # else committed an active row. If we still see none,
                # the DB is in a state we can't reason about — surface.
                raise RuntimeError(
                    f"signing-key bootstrap race resolved with neither row "
                    f"present for mirror slug={mirror.slug}"
                )
            logger.info(
                "Lost signing-key bootstrap race for mirror slug=%s; "
                "returning winner fingerprint=%s",
                mirror.slug,
                winner.gpg_fingerprint,
            )
            return winner

        self.db.refresh(row)
        # Fingerprint is public; slug is public; safe to log.
        logger.info(
            "Generated signing key for mirror slug=%s fingerprint=%s",
            mirror.slug,
            fingerprint,
        )
        return row

    # ------------------------------------------------------------------
    # Rotation (PRA-158 #5a) — two-step manual cutover
    # ------------------------------------------------------------------

    def get_pending_cutover(self, mirror_id: int) -> Optional[MirrorSigningKey]:
        return (
            self.db.query(MirrorSigningKey)
            .filter(
                MirrorSigningKey.mirror_repo_id == mirror_id,
                MirrorSigningKey.status == "pending_cutover",
            )
            .one_or_none()
        )

    def rotate_prepare(self, mirror: MirrorRepo) -> MirrorSigningKey:
        """Generate a new key as ``pending_cutover`` (PRA-158 #5a).

        Refuses if a pending_cutover key already exists for this mirror
        (operator must cut over or retire the prior prepare before
        starting another rotation). Same generation path as
        ``ensure_active`` — ephemeral GNUPGHOME, Vault write, DB row —
        only the status differs and ``armored_public_key`` lands in
        the trust bundle so hosts can install ahead of cutover.

        Per the lock: native signing still uses the prior ``active``
        key. Only ``cutover`` flips signing onto the new key.
        """
        if self.get_pending_cutover(mirror.id) is not None:
            raise RotationError(
                f"mirror '{mirror.slug}' already has a pending_cutover key; "
                "cut over or retire it before starting another rotation"
            )

        with mirror_gpg.ephemeral_gnupg_home() as home:
            fingerprint = mirror_gpg.generate_keypair(home, mirror.slug)
            private_armored = mirror_gpg.export_secret_armored(home, fingerprint)
            public_armored = mirror_gpg.export_public_armored(home, fingerprint)

        vault_path = vault_path_for(mirror.slug, fingerprint)
        wrote = self.vault.write_secret(
            vault_path,
            {
                "private_armored": private_armored,
                "public_armored": public_armored,
            },
        )
        if not wrote:
            raise RuntimeError(f"Vault write failed for rotation key at {vault_path}")

        row = MirrorSigningKey(
            mirror_repo_id=mirror.id,
            status="pending_cutover",
            gpg_fingerprint=fingerprint,
            key_uid=f"Praxis Mirror Signing {mirror.slug} {fingerprint}",
            vault_path=vault_path,
            armored_public_key=public_armored,
        )
        self.db.add(row)
        try:
            self.db.commit()
        except IntegrityError:
            # Partial-unique index for pending_cutover caught a race —
            # someone else prepared simultaneously. Drop our orphan
            # vault entry and surface so the loser sees a clean error.
            self.db.rollback()
            try:
                self.vault.delete_secret(vault_path)
            except Exception as cleanup_err:  # pylint: disable=broad-except
                logger.warning(
                    "Failed to clean up orphan vault entry at %s after "
                    "rotate-prepare race: %s",
                    vault_path,
                    cleanup_err,
                )
            raise RotationError(
                f"mirror '{mirror.slug}' had a concurrent rotate-prepare; "
                "retry to inspect the now-pending key"
            )
        self.db.refresh(row)
        logger.info(
            "rotate-prepare for mirror slug=%s pending fingerprint=%s",
            mirror.slug,
            fingerprint,
        )
        return row

    def cutover_preview(self, mirror_id: int) -> dict:
        """Compute the structured blocked-cutover host buckets.

        Returns ``{pending_fingerprint, hosts_missing_pending,
        hosts_never_installed, hosts_stale_trust_record}``.

        Bucket semantics (PRA-159 #4 fully populates the latter two):
          * ``hosts_missing_pending`` — hosts with a
            ``host_mirror_trust`` row for this mirror whose
            installed_fingerprints lacks the pending key. They have
            opted into trusting the mirror but haven't reinstalled
            since rotate-prepare.
          * ``hosts_never_installed`` — hosts whose effective content
            profile composes a channel including this mirror but that
            have NO ``host_mirror_trust`` row at all. Cutover would
            strand them because their apt/dnf wouldn't trust the
            new active key.
          * ``hosts_stale_trust_record`` — hosts that are subscribed
            (same scope as ``hosts_never_installed``), have a trust
            row, but the row is missing the CURRENT active
            fingerprint. Operator hasn't re-installed since the prior
            cutover; their next sync still works on the old active,
            but the upcoming cutover will swap to the pending key
            they don't have.

        Raises ``RotationError`` when no pending_cutover key exists.
        """
        pending = self.get_pending_cutover(mirror_id)
        if pending is None:
            raise RotationError(
                "no pending_cutover key for this mirror; run rotate-prepare first"
            )

        rows = (
            self.db.query(HostMirrorTrust)
            .filter(HostMirrorTrust.mirror_id == mirror_id)
            .all()
        )
        trust_by_host: dict[int, HostMirrorTrust] = {row.host_id: row for row in rows}
        missing_pending: List[int] = []
        for row in rows:
            installed = row.installed_fingerprints or []
            if pending.gpg_fingerprint not in installed:
                missing_pending.append(row.host_id)

        # PRA-159 #4: resolve which hosts subscribe to a content
        # profile composing this mirror, then split them into
        # never-installed vs stale-trust buckets.
        active = (
            self.db.query(MirrorSigningKey)
            .filter(
                MirrorSigningKey.mirror_repo_id == mirror_id,
                MirrorSigningKey.status == "active",
            )
            .one_or_none()
        )
        active_fp = active.gpg_fingerprint if active is not None else None

        subscribed_host_ids = self._hosts_subscribed_to_mirror(mirror_id)
        never_installed: List[int] = []
        stale_trust: List[int] = []
        for host_id in subscribed_host_ids:
            row = trust_by_host.get(host_id)
            if row is None:
                never_installed.append(host_id)
                continue
            installed = row.installed_fingerprints or []
            # "Stale" = subscribed host with a trust row whose set
            # is missing the current active fingerprint. Without an
            # active key on the mirror (signing not yet bootstrapped)
            # we can't classify staleness; skip in that case.
            if active_fp is not None and active_fp not in installed:
                stale_trust.append(host_id)

        return {
            "pending_fingerprint": pending.gpg_fingerprint,
            "hosts_missing_pending": sorted(missing_pending),
            "hosts_never_installed": sorted(never_installed),
            "hosts_stale_trust_record": sorted(stale_trust),
        }

    def _hosts_subscribed_to_mirror(self, mirror_id: int) -> List[int]:
        """Return host ids whose effective content profile composes a
        channel that includes ``mirror_id`` (PRA-159 #4).

        Walks every ``System``, runs
        ``ContentProfileService.resolve_content_for_host``, and
        keeps the host when state is ``resolved`` AND any resolved
        entry references this mirror. Hosts in no_profile / conflict
        do NOT count — they have no effective binding so the
        cutover-preview buckets shouldn't include them.

        O(N hosts × resolve cost). Fine at v1 fleet sizes; future
        optimisation could replace with a single inverse SQL
        aggregation.
        """
        # Lazy import — content_profile_service imports from
        # db.models; this module is already mid-import.
        from .content_profile_service import (  # pylint: disable=import-outside-toplevel
            ContentProfileService,
        )

        service = ContentProfileService(self.db)
        out: List[int] = []
        system_ids = [
            row[0] for row in self.db.query(System.id).all()  # type: ignore[arg-type]
        ]
        for sid in system_ids:
            resolved = service.resolve_content_for_host(sid)
            if resolved.state != "resolved":
                continue
            if any(e.mirror_id == mirror_id for e in resolved.entries):
                out.append(sid)
        return out

    def cutover(
        self,
        mirror: MirrorRepo,
        *,
        force: bool = False,
        actor_user_id: Optional[int] = None,
    ) -> MirrorSigningKey:
        """Promote ``pending_cutover`` → ``active`` and demote prior
        ``active`` → ``rotating_out`` (PRA-158 #5a).

        Hard-gated: refuses unless every host currently in
        ``host_mirror_trust`` for this mirror trusts the pending key.
        ``force=True`` skips the gate but emits a structured audit
        event with the count of hosts that were not yet ready (so a
        force-cutover is permanently visible in the audit trail).

        Returns the new active key row. Raises ``CutoverBlocked`` with
        a populated preview when the gate would refuse.
        """
        pending = self.get_pending_cutover(mirror.id)
        if pending is None:
            raise RotationError(
                "no pending_cutover key for this mirror; run rotate-prepare first"
            )

        preview = self.cutover_preview(mirror.id)
        blocked_count = (
            len(preview["hosts_missing_pending"])
            + len(preview["hosts_never_installed"])
            + len(preview["hosts_stale_trust_record"])
        )

        if blocked_count and not force:
            raise CutoverBlocked(preview)

        was_forced_override = bool(blocked_count and force)

        # Apply + commit the state transition FIRST so the audit row
        # (emitted below on a fresh session) can never describe a
        # forced cutover that didn't actually land.
        now = datetime.utcnow()
        prev_active = self.get_active(mirror.id)
        if prev_active is not None:
            prev_active.status = "rotating_out"
            prev_active.cutover_at = now
            self.db.add(prev_active)
        pending.status = "active"
        pending.cutover_at = None
        self.db.add(pending)
        self.db.commit()
        self.db.refresh(pending)
        prev_active_fingerprint = (
            prev_active.gpg_fingerprint if prev_active is not None else None
        )

        logger.info(
            "cutover mirror=%s previous_active=%s new_active=%s force=%s",
            mirror.slug,
            prev_active_fingerprint or "<none>",
            pending.gpg_fingerprint,
            force,
        )

        if was_forced_override:
            # Audit on a FRESH session (no ``db=`` kwarg → safe_emit
            # opens its own SessionLocal and closes it). The audit row
            # describes a completed override; failure to emit logs a
            # warning but doesn't undo the cutover that already
            # committed.
            from .audit_event_service import safe_emit

            safe_emit(
                action="mirror.signing_key.cutover.forced",
                actor_user_id=actor_user_id,
                target_kind="mirror",
                target_id=str(mirror.id),
                context={
                    "mirror_slug": mirror.slug,
                    "pending_fingerprint": pending.gpg_fingerprint,
                    "previous_active_fingerprint": prev_active_fingerprint,
                    "hosts_missing_pending_count": len(
                        preview["hosts_missing_pending"]
                    ),
                    "hosts_never_installed_count": len(
                        preview["hosts_never_installed"]
                    ),
                    "hosts_stale_trust_record_count": len(
                        preview["hosts_stale_trust_record"]
                    ),
                },
            )

        return pending

    def retire(self, mirror_id: int, key_id: int) -> MirrorSigningKey:
        """``rotating_out`` → ``retired`` (PRA-158 #5a).

        Refuses any other transition — only rotating_out is retire-able.
        Sets ``retired_at`` to now. Operator should rerun
        ``install-trust`` afterwards so host fingerprint sets drop the
        retired key from their on-host bundles.

        Raises ``RotationError`` for unknown key, mismatched mirror,
        or wrong source status.
        """
        key = (
            self.db.query(MirrorSigningKey)
            .filter(MirrorSigningKey.id == key_id)
            .one_or_none()
        )
        if key is None or key.mirror_repo_id != mirror_id:
            # Cross-mirror id and unknown id share the same message and
            # type so callers can't probe cross-mirror existence.
            raise RotationNotFound(
                f"signing key id={key_id} not found for mirror id={mirror_id}"
            )
        if key.status != "rotating_out":
            raise RotationError(
                f"can only retire rotating_out keys; key id={key_id} is "
                f"in status {key.status!r}"
            )

        key.status = "retired"
        key.retired_at = datetime.utcnow()
        self.db.add(key)
        self.db.commit()
        self.db.refresh(key)

        logger.info(
            "retired signing key id=%d fingerprint=%s mirror_id=%d",
            key.id,
            key.gpg_fingerprint,
            mirror_id,
        )
        return key

    def auto_retire_expired(self, mirror_id: Optional[int] = None) -> List[int]:
        """Auto-retire ``rotating_out`` keys past the configured grace
        window (PRA-158 #5a).

        Reads ``PRAXIS_MIRROR_KEY_AUTO_RETIRE_DAYS``; default unset
        means manual-only (returns empty list — no rows touched).
        Scoped to ``mirror_id`` when provided; otherwise sweeps all
        mirrors. Returns the list of newly-retired key ids.
        """
        raw = os.getenv("PRAXIS_MIRROR_KEY_AUTO_RETIRE_DAYS")
        if not raw or not raw.strip():
            return []
        try:
            days = int(raw)
        except ValueError:
            logger.warning(
                "PRAXIS_MIRROR_KEY_AUTO_RETIRE_DAYS=%r is not an integer; "
                "auto-retire disabled",
                raw,
            )
            return []
        if days < 0:
            return []

        cutoff = datetime.utcnow() - timedelta(days=days)
        query = self.db.query(MirrorSigningKey).filter(
            MirrorSigningKey.status == "rotating_out",
            MirrorSigningKey.cutover_at.isnot(None),
            MirrorSigningKey.cutover_at < cutoff,
        )
        if mirror_id is not None:
            query = query.filter(MirrorSigningKey.mirror_repo_id == mirror_id)

        retired_ids: List[int] = []
        now = datetime.utcnow()
        for key in query.all():
            key.status = "retired"
            key.retired_at = now
            self.db.add(key)
            retired_ids.append(key.id)

        if retired_ids:
            self.db.commit()
            logger.info(
                "auto-retired %d signing key(s) past %d-day grace: ids=%s",
                len(retired_ids),
                days,
                retired_ids,
            )
        return retired_ids
