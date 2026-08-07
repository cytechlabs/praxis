"""Airgap export orchestrator (PRA-160 slices #1 + #2).

Slice #1 surface (descriptor-ready end state):
  1. Plan the bundle (validation, byte-match check, descriptor body).
  2. Insert ``airgap_bundles`` row as ``status='building'``.
  3. Load the active bundle signing key (creates one if absent).
  4. Pull the private key out of Vault, sign + write the descriptor
     in a single ephemeral GNUPGHOME pass, drop the private reference.
  5. Update the row to ``status='descriptor_ready'`` with
     ``bundle_descriptor_path`` populated.
  6. Emit ``airgap_bundle.descriptor_ready`` audit on a fresh session.

Slice #2 surface (descriptor-ready → ok):
  7. ``build_bundle_payload(bundle_id)`` resumes from
     ``status='descriptor_ready'``. Computes ``payload_index`` over
     every mirror's manifest sidecars + live tree, stamps the index
     + per-mirror in-tar paths onto the descriptor, re-signs (the
     descriptor_signer's atomic-dir promotion handles the swap),
     assembles a deterministic POSIX tar at
     ``<airgap_bundle_root>/<bundle_id>.tar``, then transitions the
     row to ``status='ok'`` with
     ``bundle_path``/``payload_sha256``/``byte_count`` populated.
     Audits ``airgap_bundle.ok`` on a fresh session.

Locks (PRA-160 design conversation):
  * Planner refusals do **not** create an ``airgap_bundles`` row;
    they emit ``airgap_export_refused`` audit only. Row creation is
    gated on a successful plan.
  * Failure between row insert and ``descriptor_ready`` transitions
    the row to ``status='failed'`` with structured ``error_text`` so
    a future operator query (``status='failed' AND
    bundle_descriptor_path IS NULL``) finds these.
  * **Slice #2 failure path nulls BOTH** ``bundle_descriptor_path``
    AND ``bundle_path`` on transition to ``failed`` — the descriptor
    signer's worst-case double-rename can leave the canonical
    descriptor path empty, and any failed tar assembly leaves no
    valid bundle file at the canonical path. Pointers to missing
    canonical paths are more misleading than helpful.
  * ``build_bundle_payload`` is idempotent on ``status='ok'``
    (returns the row as-is) so a re-fired ``BackgroundTasks`` after
    a successful build doesn't double-build. Refuses on
    ``failed``/``building``: operator must ``POST /airgap/exports``
    again to start a fresh attempt.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from ...db.models import AirgapBundle, AirgapBundleSigningKey
from ..audit_event_service import safe_emit
from ..vault_service import VaultService
from .descriptor_signer import sign_and_write_descriptor
from .planner import AirgapPlanner, PlannerRefusal, serialize_request_for_audit
from .schema import deserialize_descriptor
from .signing_key_service import AirgapBundleSigningKeyService
from .tar_assembler import (
    PayloadIndexError,
    assemble_bundle_tar,
    compute_delta_payload_index,
    compute_payload_index,
)

logger = logging.getLogger(__name__)


def _sha256_file(path: Path) -> str:
    """Stream-hash ``path`` in 1 MiB chunks. Returns hex sha256.

    Used by the idempotent-ok verifier to compare an existing
    bundle file against ``airgap_bundles.payload_sha256``.
    """
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class AirgapExportOrchestrator:
    """Slice #1 end-to-end: plan → row → sign descriptor → ready."""

    def __init__(
        self,
        db: Session,
        vault: Optional[VaultService] = None,
    ) -> None:
        self.db = db
        self.vault = vault if vault is not None else VaultService(db)
        self.signing = AirgapBundleSigningKeyService(db, vault=self.vault)
        self.planner = AirgapPlanner(db)

    def create_descriptor_export(
        self,
        *,
        profile_slugs: List[str],
        snapshot_selector_base: str,
        snapshot_overrides: Optional[Dict[str, int]],
        kind: str,
        parent_bundle_id: Optional[str],
        actor_user_id: Optional[int],
    ) -> AirgapBundle:
        """End-to-end slice-#1 descriptor build.

        Returns the ``AirgapBundle`` row in ``status='descriptor_ready'``
        on success. Raises ``PlannerRefusal`` (caller maps to 422) on
        validation failure — no row created.
        """
        request_audit_payload = serialize_request_for_audit(
            profile_slugs=profile_slugs,
            snapshot_selector_base=snapshot_selector_base,
            snapshot_overrides=snapshot_overrides,
            kind=kind,
            parent_bundle_id=parent_bundle_id,
        )

        # Step 1: ensure the active bundle signing key. Done BEFORE
        # planning so we have a fingerprint to embed in the descriptor.
        signing_key = self.signing.ensure_active()

        # Step 2: plan. Refusals propagate up without any row insert.
        try:
            descriptor = self.planner.plan(
                profile_slugs=profile_slugs,
                snapshot_selector_base=snapshot_selector_base,
                snapshot_overrides=snapshot_overrides,
                kind=kind,
                parent_bundle_id=parent_bundle_id,
                bundle_signing_fingerprint=signing_key.gpg_fingerprint,
            )
        except PlannerRefusal as exc:
            # Audit on a fresh session — the refusal isn't tied to any
            # particular DB transaction and shouldn't be lost if the
            # caller's session rolls back later. Use
            # ``airgap_export_request`` with a deterministic hash of
            # the canonical request body as ``target_id`` so two
            # identical refusals share an audit identity (groupable
            # in dashboards) and audit-by-target queries work without
            # the placeholder ``-``.
            # 32 hex chars (128 bits) is wide enough for
            # forensic searches in a busy fleet without being
            # unwieldy in audit views. 16 hex was statistically fine
            # for "this distinct request" identity but felt thin for
            # ops at scale.
            request_hash = hashlib.sha256(
                request_audit_payload.encode("utf-8")
            ).hexdigest()[:32]
            safe_emit(
                action="airgap_export_refused",
                actor_user_id=actor_user_id,
                target_kind="airgap_export_request",
                target_id=request_hash,
                context={
                    "code": exc.code,
                    "message": str(exc),
                    "request": request_audit_payload,
                    **exc.context,
                },
            )
            raise

        started_at = datetime.utcnow()
        row = AirgapBundle(
            bundle_id=descriptor.bundle_id,
            kind=descriptor.kind,
            parent_bundle_id=descriptor.parent_bundle_id,
            status="building",
            signing_key_id=signing_key.id,
            request_payload=request_audit_payload,
            started_at=started_at,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)

        try:
            private_armored = self._read_private_armored(signing_key)
            body_path, _sig_path = sign_and_write_descriptor(
                descriptor=descriptor,
                signing_key=signing_key,
                private_armored=private_armored,
            )
            del private_armored  # drop the reference promptly
        except Exception as exc:  # pylint: disable=broad-except
            # When a row transitions to ``failed``, null
            # ``bundle_descriptor_path``. In slice #1 the column is
            # not yet set when descriptor-sign fails, but slice #2's
            # re-sign path will have a populated value from the
            # first sign — and the descriptor_signer's worst-case
            # double-rename failure can leave the canonical path
            # empty on disk. A pointer to a missing canonical path
            # is more misleading than helpful, so clear it.
            row.bundle_descriptor_path = None
            row.status = "failed"
            row.error_text = f"descriptor signing failed: {exc!r}"
            row.finished_at = datetime.utcnow()
            self.db.add(row)
            self.db.commit()
            self.db.refresh(row)
            safe_emit(
                action="airgap_bundle.failed",
                actor_user_id=actor_user_id,
                target_kind="airgap_bundle",
                target_id=row.bundle_id,
                context={
                    "kind": row.kind,
                    "stage": "descriptor_sign",
                    "error_text": row.error_text,
                },
            )
            raise

        row.bundle_descriptor_path = str(body_path)
        row.status = "descriptor_ready"
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)

        safe_emit(
            action="airgap_bundle.descriptor_ready",
            actor_user_id=actor_user_id,
            target_kind="airgap_bundle",
            target_id=row.bundle_id,
            context={
                "kind": row.kind,
                "parent_bundle_id": row.parent_bundle_id,
                "signing_fingerprint": signing_key.gpg_fingerprint,
                "bundle_descriptor_path": row.bundle_descriptor_path,
                "profile_count": len(descriptor.profiles),
                "channel_count": len(descriptor.channels),
                "mirror_count": len(descriptor.mirrors),
            },
        )

        logger.info(
            "Airgap descriptor ready bundle_id=%s kind=%s mirrors=%d",
            row.bundle_id,
            row.kind,
            len(descriptor.mirrors),
        )
        return row

    def _verify_bundle_on_disk(
        self,
        row: AirgapBundle,
        *,
        actor_user_id: Optional[int],
    ) -> None:
        """Check the on-disk tar still matches the row.

        Re-fired BackgroundTasks (or operator-driven re-call) on a
        ``status='ok'`` row would otherwise short-circuit unconditionally.
        If the file was removed or mutated since the build landed,
        the short-circuit returns ``ok`` with a stale pointer —
        which #1-c locked as actively misleading. Instead, transition
        to ``failed`` via ``_fail_build`` (descriptor pointer preserved
        per #2-a P3 since this isn't a descriptor-invalidating stage)
        and re-raise so the caller sees the change.
        """
        if not row.bundle_path:
            self._fail_build(
                row,
                actor_user_id=actor_user_id,
                stage="bundle_path_missing",
                error_text=(
                    "row at status='ok' has no bundle_path; on-disk "
                    "artifact pointer was lost"
                ),
            )
            raise RuntimeError(
                f"airgap bundle {row.bundle_id!r} ok-row has no bundle_path"
            )
        bundle_file = Path(row.bundle_path)
        if not bundle_file.exists():
            self._fail_build(
                row,
                actor_user_id=actor_user_id,
                stage="bundle_path_missing",
                error_text=(
                    f"bundle file {bundle_file} does not exist; the "
                    "on-disk artifact was removed after build"
                ),
            )
            raise RuntimeError(
                f"airgap bundle {row.bundle_id!r} bundle_path missing on disk"
            )
        if not row.payload_sha256:
            # Defensive: a row at ``ok`` without payload_sha256 is a
            # schema-state contradiction. Treat as failed.
            self._fail_build(
                row,
                actor_user_id=actor_user_id,
                stage="payload_sha_mismatch",
                error_text="row at status='ok' has no payload_sha256",
            )
            raise RuntimeError(
                f"airgap bundle {row.bundle_id!r} ok-row has no payload_sha256"
            )

        actual_sha = _sha256_file(bundle_file)
        if actual_sha != row.payload_sha256:
            self._fail_build(
                row,
                actor_user_id=actor_user_id,
                stage="payload_sha_mismatch",
                error_text=(
                    f"on-disk sha256 {actual_sha!r} does not match row "
                    f"payload_sha256 {row.payload_sha256!r}; bundle file "
                    "was mutated after build"
                ),
            )
            raise RuntimeError(
                f"airgap bundle {row.bundle_id!r} payload_sha256 mismatch"
            )

    def _load_parent_descriptor(self, parent_bundle_id: Optional[str]):
        """Load the parent bundle's descriptor from disk for delta planning.

        PRA-160 slice #4: the planner already validated that the
        parent row exists, is ``status='ok'``, and its
        ``bundle_descriptor_path`` is present on disk. We reload
        here at tar-assembly time to feed
        ``compute_delta_payload_index``. If the descriptor
        disappeared between planner validation and tar assembly,
        this raises ``RuntimeError`` and the caller's ``_fail_build``
        path catches it with stage='payload_index'.
        """
        from ...db.models import AirgapBundle  # pylint: disable=import-outside-toplevel
        from .schema import (  # pylint: disable=import-outside-toplevel
            deserialize_descriptor,
        )

        if not parent_bundle_id:
            raise RuntimeError(
                "delta build requires parent_bundle_id; descriptor has none"
            )
        row = (
            self.db.query(AirgapBundle)
            .filter(AirgapBundle.bundle_id == parent_bundle_id)
            .one_or_none()
        )
        if row is None or not row.bundle_descriptor_path:
            raise RuntimeError(
                f"parent bundle {parent_bundle_id!r} or its descriptor path "
                "vanished between planner validation and tar assembly"
            )
        return deserialize_descriptor(Path(row.bundle_descriptor_path).read_bytes())

    def _read_private_armored(self, key: AirgapBundleSigningKey) -> str:
        secret = self.vault.read_secret(key.vault_path)
        if not secret or "private_armored" not in secret:
            raise RuntimeError(
                f"airgap signing key {key.gpg_fingerprint} has no private "
                f"material at vault path {key.vault_path}"
            )
        return secret["private_armored"]

    # ------------------------------------------------------------------
    # Slice #2: descriptor_ready → ok
    # ------------------------------------------------------------------

    def build_bundle_payload(
        self,
        *,
        bundle_id: str,
        actor_user_id: Optional[int],
    ) -> AirgapBundle:
        """Assemble the tar for a ``descriptor_ready`` bundle.

        Returns the row at ``status='ok'`` on success. Idempotent on
        ``status='ok'`` (returns the row unchanged so a re-fired
        BackgroundTask doesn't double-build). Refuses on
        ``failed``/``building`` (operator must POST a new export).

        Failure path: row → ``failed`` with
        ``bundle_descriptor_path = None`` and ``bundle_path = None``,
        ``error_text`` populated, ``finished_at`` set, and an
        ``airgap_bundle.failed`` audit emitted on a fresh session.
        """
        row = (
            self.db.query(AirgapBundle)
            .filter(AirgapBundle.bundle_id == bundle_id)
            .one_or_none()
        )
        if row is None:
            raise RuntimeError(f"airgap bundle bundle_id={bundle_id!r} not found")

        if row.status == "ok":
            # Before short-circuiting, verify the
            # on-disk artifact still matches the row. If the bundle
            # file was deleted (operator cleanup, FS corruption) or
            # mutated (sha drift), the row's pointer is stale;
            # transitioning to ``failed`` is more honest than
            # returning ``ok`` with a broken pointer.
            self._verify_bundle_on_disk(row, actor_user_id=actor_user_id)
            return row
        if row.status != "descriptor_ready":
            raise RuntimeError(
                f"airgap bundle {bundle_id!r} is in status {row.status!r}; "
                "build_bundle_payload requires status='descriptor_ready'"
            )
        if not row.bundle_descriptor_path:
            raise RuntimeError(
                f"airgap bundle {bundle_id!r} has no bundle_descriptor_path; "
                "cannot resume tar assembly"
            )

        # Transition to building before we touch disk so a concurrent
        # poll sees the in-progress state.
        row.status = "building"
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)

        signing_key = (
            self.db.query(AirgapBundleSigningKey)
            .filter(AirgapBundleSigningKey.id == row.signing_key_id)
            .one_or_none()
        )
        if signing_key is None:
            self._fail_build(
                row,
                actor_user_id=actor_user_id,
                stage="signing_key_lookup",
                error_text=(
                    f"signing_key_id={row.signing_key_id!r} not found; "
                    "cannot re-sign descriptor"
                ),
            )
            raise RuntimeError(f"signing key for bundle {bundle_id!r} is missing")

        try:
            logger.info(
                "Loading slice-#1 descriptor for bundle_id=%s from %s",
                row.bundle_id,
                row.bundle_descriptor_path,
            )
            descriptor_body = Path(row.bundle_descriptor_path).read_bytes()
            descriptor = deserialize_descriptor(descriptor_body)
        except Exception as exc:  # pylint: disable=broad-except
            self._fail_build(
                row,
                actor_user_id=actor_user_id,
                stage="descriptor_reload",
                error_text=f"reload of descriptor body failed: {exc!r}",
            )
            raise

        try:
            if descriptor.kind == "delta":
                # PRA-160 slice #4: per-file diff against the parent.
                # The parent's descriptor is on disk at the parent's
                # bundle_descriptor_path; load it, then reduce the
                # current member set to only those files that differ.
                parent_descriptor = self._load_parent_descriptor(
                    descriptor.parent_bundle_id
                )
                payload_index, member_plans = compute_delta_payload_index(
                    descriptor, parent_descriptor
                )
            else:
                payload_index, member_plans = compute_payload_index(descriptor)
        except PayloadIndexError as exc:
            self._fail_build(
                row,
                actor_user_id=actor_user_id,
                stage="payload_index",
                error_text=str(exc),
            )
            raise
        except Exception as exc:  # pylint: disable=broad-except
            self._fail_build(
                row,
                actor_user_id=actor_user_id,
                stage="payload_index",
                error_text=f"payload index computation failed: {exc!r}",
            )
            raise

        # Stamp the populated index + per-mirror in-tar paths onto
        # the descriptor. The bundle-level signature recomputed below
        # then covers ``payload_index``, which is what the importer
        # uses to verify each member's sha256.
        descriptor.payload_index = payload_index
        for mirror in descriptor.mirrors:
            slug = mirror.mirror_slug
            mirror.manifest_path_in_tar = (
                f"mirrors/{slug}/snapshots/{mirror.run_id}.manifest.json"
            )
            mirror.manifest_signature_path_in_tar = (
                f"mirrors/{slug}/snapshots/{mirror.run_id}.manifest.json.sig"
            )
            mirror.live_path_in_tar = f"mirrors/{slug}/live"

        try:
            private_armored = self._read_private_armored(signing_key)
            body_path, sig_path = sign_and_write_descriptor(
                descriptor=descriptor,
                signing_key=signing_key,
                private_armored=private_armored,
            )
            del private_armored
        except Exception as exc:  # pylint: disable=broad-except
            self._fail_build(
                row,
                actor_user_id=actor_user_id,
                stage="descriptor_resign",
                error_text=f"descriptor re-sign failed: {exc!r}",
            )
            raise

        try:
            final_path, payload_sha256, byte_count = assemble_bundle_tar(
                bundle_id=row.bundle_id,
                descriptor_body_path=body_path,
                descriptor_signature_path=sig_path,
                member_plans=member_plans,
                payload_index=payload_index,
            )
        except Exception as exc:  # pylint: disable=broad-except
            self._fail_build(
                row,
                actor_user_id=actor_user_id,
                stage="tar_assembly",
                error_text=f"tar assembly failed: {exc!r}",
            )
            raise

        row.bundle_path = str(final_path)
        row.payload_sha256 = payload_sha256
        row.byte_count = byte_count
        row.status = "ok"
        row.finished_at = datetime.utcnow()
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)

        safe_emit(
            action="airgap_bundle.ok",
            actor_user_id=actor_user_id,
            target_kind="airgap_bundle",
            target_id=row.bundle_id,
            context={
                "kind": row.kind,
                "bundle_path": row.bundle_path,
                "payload_sha256": row.payload_sha256,
                "byte_count": row.byte_count,
                "payload_member_count": len(payload_index),
            },
        )

        logger.info(
            "Airgap bundle ok bundle_id=%s bytes=%d members=%d",
            row.bundle_id,
            byte_count,
            len(payload_index),
        )
        return row

    # Stage-aware ``bundle_descriptor_path`` nulling.
    # Stages where the descriptor body on disk MAY be invalid:
    #   * descriptor_reload — read failed; the file might be gone.
    #   * descriptor_resign — the descriptor_signer's atomic-dir
    #     promotion can leave the canonical path empty in its
    #     worst-case double-rename branch.
    # Stages that DO NOT touch the descriptor path on disk and
    # therefore preserve the slice-#1 pointer:
    #   * signing_key_lookup, payload_index, tar_assembly,
    #     bundle_path_missing, payload_sha_mismatch.
    _DESCRIPTOR_INVALIDATING_STAGES = frozenset(
        {"descriptor_reload", "descriptor_resign"}
    )

    def _fail_build(
        self,
        row: AirgapBundle,
        *,
        actor_user_id: Optional[int],
        stage: str,
        error_text: str,
    ) -> None:
        """Transition ``row`` to ``failed`` and emit the audit.

        Scope ``bundle_descriptor_path`` nulling to
        stages whose failure mode actually invalidates the on-disk
        descriptor (descriptor_reload, descriptor_resign).
        Payload-index and tar-assembly failures preserve the
        slice-#1 descriptor pointer so an operator inspecting the
        failed row still has a valid file at the canonical path.
        ``bundle_path`` is always nulled — a partial / failed tar
        write produces no usable bundle file.
        """
        row.status = "failed"
        if stage in self._DESCRIPTOR_INVALIDATING_STAGES:
            row.bundle_descriptor_path = None
        row.bundle_path = None
        row.error_text = error_text
        row.finished_at = datetime.utcnow()
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        safe_emit(
            action="airgap_bundle.failed",
            actor_user_id=actor_user_id,
            target_kind="airgap_bundle",
            target_id=row.bundle_id,
            context={
                "kind": row.kind,
                "stage": stage,
                "error_text": error_text,
            },
        )


# ---------------------------------------------------------------------------
# BackgroundTasks entry point (PRA-160 slice #2)
# ---------------------------------------------------------------------------


def run_build_in_background(bundle_id: str, actor_user_id: Optional[int]) -> None:
    """Entry point for FastAPI's BackgroundTasks.

    Opens its own ``SessionLocal`` (the request session that
    scheduled the task is already closed by the time this runs) and
    calls ``build_bundle_payload``. Mirrors PRA-157's
    ``claim_and_sync_one_mirror`` shape — keeps task wiring out of
    the orchestrator class so route code stays simple
    (``background_tasks.add_task(run_build_in_background, ...)``).

    Exceptions from ``build_bundle_payload`` are already converted
    to ``status='failed'`` row state + audit before they propagate;
    we catch and log here so a stray exception doesn't poison the
    BackgroundTasks worker.
    """
    from ...db.session import SessionLocal  # pylint: disable=import-outside-toplevel

    db = SessionLocal()
    try:
        orchestrator = AirgapExportOrchestrator(db)
        try:
            orchestrator.build_bundle_payload(
                bundle_id=bundle_id, actor_user_id=actor_user_id
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.error(
                "Airgap bundle build failed bundle_id=%s: %r",
                bundle_id,
                exc,
            )
    finally:
        db.close()
