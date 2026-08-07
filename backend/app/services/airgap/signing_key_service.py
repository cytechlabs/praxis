"""Instance-wide airgap bundle signing key (PRA-160 slice #1).

Single ``active`` key per Praxis instance. Mirrors the
``MirrorSigningKeyService.ensure_active`` shape but is instance
scoped, not per-mirror — bundle descriptors are signed by the
instance, not by any one mirror.

Locks (PRA-160 design conversation):
  * Vault path: ``praxis/bundle-signing-key/<gpg_fingerprint>``.
  * Vault payload: ``{"private_armored": ..., "public_armored": ...}``.
    Public is duplicated into Vault for round-trip integrity; the
    DB row also caches ``armored_public_key`` so verify-side reads
    never touch private material (PRA-158 #3a pattern).
  * Generation runs under an ephemeral GNUPGHOME (reuses
    ``mirror_gpg.ephemeral_gnupg_home`` — same forbidden-prefix
    guard, same wipe-on-exit).
  * Concurrent bootstrap: partial unique index
    ``uq_airgap_bundle_signing_keys_one_active`` resolves the race
    via IntegrityError; loser drops orphan vault entry and re-fetches.
  * NEVER logs key material; NEVER logs GNUPGHOME contents. Logs
    fingerprints (public) only.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...db.models import AirgapBundleSigningKey
from .. import mirror_gpg
from ..vault_service import VaultService

logger = logging.getLogger(__name__)

VAULT_PATH_PREFIX = "praxis/bundle-signing-key"


class SigningKeyError(RuntimeError):
    """Base class for airgap bundle signing-key lifecycle refusals (PRA-196)."""


class SigningKeyNotFound(SigningKeyError):
    """No bundle signing key with the given id."""


class NoActiveKeyToRotate(SigningKeyError):
    """Rotation requested but no active key exists; bootstrap one first."""


class RetireActiveKeyRefused(SigningKeyError):
    """Refusal: the active bundle signing key cannot be retired (rotate first)."""


# Slug used for the GPG uid + key generation seed; bundle key is
# instance-wide so there's no per-mirror slug to thread through.
# ``praxis-airgap`` is descriptive in ``gpg --list-keys`` output and
# matches the eventual CLI command name.
_BUNDLE_KEY_SLUG = "praxis-airgap"


def vault_path_for(fingerprint: str) -> str:
    """Compose the Vault KV path for a bundle signing key."""
    return f"{VAULT_PATH_PREFIX}/{fingerprint}"


class AirgapBundleSigningKeyService:
    """Manage the instance-wide airgap bundle signing key (PRA-160)."""

    def __init__(self, db: Session, vault: Optional[VaultService] = None):
        self.db = db
        self.vault = vault if vault is not None else VaultService(db)

    # ------------------------------------------------------------------
    # Read paths
    # ------------------------------------------------------------------

    def get_active(self) -> Optional[AirgapBundleSigningKey]:
        """Return the current active key, or ``None`` if not bootstrapped."""
        return (
            self.db.query(AirgapBundleSigningKey)
            .filter(AirgapBundleSigningKey.status == "active")
            .one_or_none()
        )

    def get(self, key_id: int) -> Optional[AirgapBundleSigningKey]:
        """Return one bundle signing key by id, or ``None``."""
        return (
            self.db.query(AirgapBundleSigningKey)
            .filter(AirgapBundleSigningKey.id == key_id)
            .one_or_none()
        )

    def list_keys(self) -> List[AirgapBundleSigningKey]:
        """Return all bundle signing keys, newest first (PRA-196).

        Includes ``active``, ``rotating_out``, and ``retired`` rows so the
        operator UI can show the current key plus verification-only and
        fully-retired history. No private material is read here — the armored
        public key is cached on each row.
        """
        return (
            self.db.query(AirgapBundleSigningKey)
            .order_by(AirgapBundleSigningKey.created_at.desc())
            .all()
        )

    def get_public_armored(self, key: AirgapBundleSigningKey) -> str:
        """Return the armored public key for ``key``.

        Hot path is the DB column (PRA-158 #3a pattern). Falls back
        to Vault if the column is somehow empty — that should never
        happen for keys created by ``ensure_active`` since the column
        is populated at insert time.
        """
        if key.armored_public_key:
            return key.armored_public_key

        secret = self.vault.read_secret(key.vault_path)
        if not secret or "public_armored" not in secret:
            raise RuntimeError(
                f"airgap signing key {key.gpg_fingerprint} has no public "
                f"material in DB or vault at {key.vault_path}"
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

    def ensure_active(self) -> AirgapBundleSigningKey:
        """Return the active key, generating one if absent.

        Idempotent: callers can invoke this on every export start
        without worrying about duplicate rows. The Vault write +
        DB row insert sequence mirrors
        ``MirrorSigningKeyService.ensure_active`` — see PRA-158 #1
        and #1-a for the race-recovery contract.
        """
        existing = self.get_active()
        if existing is not None:
            return existing

        fingerprint, public_armored, vault_path = self._generate_and_store_material()

        row = self._build_row("active", fingerprint, public_armored, vault_path)
        self.db.add(row)
        try:
            self.db.commit()
        except IntegrityError:
            # Concurrent bootstrap won the race. Drop our orphan
            # Vault entry (the winner's row points at a different
            # fingerprint) and return the winner.
            self.db.rollback()
            try:
                self.vault.delete_secret(vault_path)
            except Exception as cleanup_err:  # pylint: disable=broad-except
                logger.warning(
                    "Failed to clean up orphan vault entry at %s after "
                    "airgap signing-key bootstrap race: %s",
                    vault_path,
                    cleanup_err,
                )
            winner = self.get_active()
            if winner is None:
                raise RuntimeError(
                    "airgap signing-key bootstrap race resolved with neither "
                    "row present"
                )
            logger.info(
                "Lost airgap signing-key bootstrap race; returning winner "
                "fingerprint=%s",
                winner.gpg_fingerprint,
            )
            return winner

        self.db.refresh(row)
        logger.info(
            "Generated airgap bundle signing key fingerprint=%s",
            fingerprint,
        )
        return row

    def rotate(self) -> Tuple[AirgapBundleSigningKey, AirgapBundleSigningKey]:
        """Rotate the active bundle signing key (PRA-196).

        Demotes the current ``active`` key to ``rotating_out`` (kept for
        verifying already-exported bundles) and generates a fresh ``active``
        key. Returns ``(old_active, new_active)``. Requires an existing active
        key — call :meth:`ensure_active` to bootstrap first.

        Operator note: bundles produced AFTER this call are signed by the new
        key, so the import-side instance must pin the new public key before
        importing them. The old key stays valid for verifying previously
        exported bundles until it is retired.

        The new key material is generated + written to Vault BEFORE the DB
        transition so a gpg/Vault failure never leaves the instance without an
        active key. The demote+insert runs in one transaction: the one-active
        partial unique index tolerates it because the old row leaves ``active``
        before the new row enters it.
        """
        active = self.get_active()
        if active is None:
            raise NoActiveKeyToRotate(
                "no active bundle signing key to rotate; bootstrap one first"
            )

        fingerprint, public_armored, vault_path = self._generate_and_store_material()

        active.status = "rotating_out"
        self.db.add(active)
        self.db.flush()  # vacate the single active slot before inserting the new key

        new_row = self._build_row("active", fingerprint, public_armored, vault_path)
        self.db.add(new_row)
        try:
            self.db.commit()
        except IntegrityError:
            self.db.rollback()
            try:
                self.vault.delete_secret(vault_path)
            except Exception as cleanup_err:  # pylint: disable=broad-except
                logger.warning(
                    "Failed to clean up orphan vault entry at %s after airgap "
                    "signing-key rotation race: %s",
                    vault_path,
                    cleanup_err,
                )
            raise
        self.db.refresh(active)
        self.db.refresh(new_row)
        logger.info(
            "Rotated airgap bundle signing key old_fingerprint=%s "
            "new_fingerprint=%s",
            active.gpg_fingerprint,
            new_row.gpg_fingerprint,
        )
        return active, new_row

    def retire(self, key_id: int) -> AirgapBundleSigningKey:
        """Retire a ``rotating_out`` bundle signing key (PRA-196).

        Marks the key ``retired`` so it is no longer offered for distribution.
        Refuses to retire the ``active`` key (rotate first). Idempotent on an
        already-``retired`` key.
        """
        row = self.get(key_id)
        if row is None:
            raise SigningKeyNotFound(f"airgap bundle signing key id={key_id} not found")
        if row.status == "active":
            raise RetireActiveKeyRefused(
                "cannot retire the active bundle signing key; rotate to a new "
                "active key first"
            )
        if row.status == "retired":
            return row
        row.status = "retired"
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        logger.info(
            "Retired airgap bundle signing key id=%d fingerprint=%s",
            row.id,
            row.gpg_fingerprint,
        )
        return row

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _generate_and_store_material(self) -> Tuple[str, str, str]:
        """Generate a GPG keypair under an ephemeral GNUPGHOME and write the
        private/public armored material to Vault. Returns
        ``(fingerprint, public_armored, vault_path)``. Never logs key material.
        """
        with mirror_gpg.ephemeral_gnupg_home() as home:
            fingerprint = mirror_gpg.generate_keypair(home, _BUNDLE_KEY_SLUG)
            private_armored = mirror_gpg.export_secret_armored(home, fingerprint)
            public_armored = mirror_gpg.export_public_armored(home, fingerprint)

        vault_path = vault_path_for(fingerprint)
        wrote = self.vault.write_secret(
            vault_path,
            {
                "private_armored": private_armored,
                "public_armored": public_armored,
            },
        )
        if not wrote:
            raise RuntimeError(
                f"Vault write failed for airgap bundle signing key at {vault_path}"
            )
        return fingerprint, public_armored, vault_path

    def _build_row(
        self, status: str, fingerprint: str, public_armored: str, vault_path: str
    ) -> AirgapBundleSigningKey:
        return AirgapBundleSigningKey(
            status=status,
            gpg_fingerprint=fingerprint,
            key_uid=f"Praxis Airgap Bundle Signing {fingerprint}",
            vault_path=vault_path,
            armored_public_key=public_armored,
        )
