"""Operator-pinned bundle public keys for airgap import (PRA-160 slice #3).

The importer trusts only keys whose ``deleted_at IS NULL`` rows
exist in ``airgap_import_trust_keys``. Armored bytes carried inside
a bundle tar are NOT trust anchors.

Locks:
  * ``add_armored_public_key`` derives the fingerprint via gpg
    --import + --list-keys (reuses ``mirror_gpg.import_public_and_extract_fingerprint``)
    so we never trust an operator-supplied fingerprint string.
    Single-primary-key armor is required (multi-primary refuses).
  * Re-pinning a previously-soft-deleted fingerprint creates a
    fresh row — separate ``added_at`` for audit clarity.
  * Active-fingerprint uniqueness is enforced via the partial
    unique index ``WHERE deleted_at IS NULL``; a duplicate active
    pin raises ``ImportTrustKeyExists``.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...db.models import AirgapImportTrustKey
from .. import mirror_gpg

logger = logging.getLogger(__name__)


class ImportTrustKeyExists(RuntimeError):
    """Refusal: an active trust pin for this fingerprint already exists.

    Soft-deleted prior pins do NOT count (the partial unique index
    only covers active rows). To re-pin after delete, the caller
    submits the same armored key again and gets a fresh row.
    """


class ImportTrustKeyService:
    """CRUD for operator-pinned bundle trust keys."""

    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def list_active(self) -> List[AirgapImportTrustKey]:
        """Return active (non-deleted) trust pins ordered by added_at desc."""
        return (
            self.db.query(AirgapImportTrustKey)
            .filter(AirgapImportTrustKey.deleted_at.is_(None))
            .order_by(AirgapImportTrustKey.added_at.desc())
            .all()
        )

    def list_all(self) -> List[AirgapImportTrustKey]:
        """Return all rows including soft-deleted (audit view)."""
        return (
            self.db.query(AirgapImportTrustKey)
            .order_by(AirgapImportTrustKey.added_at.desc())
            .all()
        )

    def get(self, key_id: int) -> Optional[AirgapImportTrustKey]:
        return (
            self.db.query(AirgapImportTrustKey)
            .filter(AirgapImportTrustKey.id == key_id)
            .one_or_none()
        )

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def add_armored_public_key(self, armored_public_key: str) -> AirgapImportTrustKey:
        """Import the armored key into an ephemeral keyring, derive
        the fingerprint, and persist a trust pin row.

        Refuses ``ImportTrustKeyExists`` if an active row for the
        same fingerprint already exists.
        """
        with mirror_gpg.ephemeral_gnupg_home() as home:
            fingerprint = mirror_gpg.import_public_and_extract_fingerprint(
                home, armored_public_key
            )
            # Pull the uid from --list-keys output. Best-effort —
            # we already have the fingerprint, so a missing uid is
            # cosmetic. Use a fallback string.
            key_uid = _extract_uid_or_fallback(home, fingerprint)

        existing_active = (
            self.db.query(AirgapImportTrustKey)
            .filter(
                AirgapImportTrustKey.gpg_fingerprint == fingerprint,
                AirgapImportTrustKey.deleted_at.is_(None),
            )
            .one_or_none()
        )
        if existing_active is not None:
            raise ImportTrustKeyExists(
                f"airgap import trust key fingerprint={fingerprint} "
                f"already pinned (id={existing_active.id})"
            )

        row = AirgapImportTrustKey(
            gpg_fingerprint=fingerprint,
            key_uid=key_uid,
            armored_public_key=armored_public_key,
        )
        self.db.add(row)
        try:
            self.db.commit()
        except IntegrityError as exc:
            # Concurrent add raced past the read; the partial unique
            # index caught it. Re-fetch and surface the existing.
            self.db.rollback()
            winner = (
                self.db.query(AirgapImportTrustKey)
                .filter(
                    AirgapImportTrustKey.gpg_fingerprint == fingerprint,
                    AirgapImportTrustKey.deleted_at.is_(None),
                )
                .one_or_none()
            )
            if winner is None:
                raise RuntimeError(
                    f"trust key add raced and neither row landed for "
                    f"fingerprint={fingerprint}"
                ) from exc
            raise ImportTrustKeyExists(
                f"airgap import trust key fingerprint={fingerprint} "
                f"already pinned (id={winner.id})"
            ) from exc

        self.db.refresh(row)
        logger.info(
            "Pinned airgap import trust key fingerprint=%s key_uid=%r",
            fingerprint,
            key_uid,
        )
        return row

    def soft_delete(self, key_id: int) -> AirgapImportTrustKey:
        """Mark a trust pin as deleted. Idempotent on already-deleted."""
        row = self.get(key_id)
        if row is None:
            raise RuntimeError(f"airgap import trust key id={key_id} not found")
        if row.deleted_at is None:
            row.deleted_at = datetime.utcnow()
            self.db.add(row)
            self.db.commit()
            self.db.refresh(row)
            logger.info(
                "Soft-deleted airgap import trust key id=%d fingerprint=%s",
                row.id,
                row.gpg_fingerprint,
            )
        return row


def _extract_uid_or_fallback(home, fingerprint: str) -> str:
    """Best-effort uid extraction from gpg --with-colons --list-keys.

    Falls back to ``f"<fingerprint {fingerprint}>"`` if the uid
    line isn't present (shouldn't happen for a well-formed armor
    but we don't want to fail key registration over a cosmetic
    field).
    """
    import re  # pylint: disable=import-outside-toplevel

    try:
        result = mirror_gpg._run_gpg(  # pylint: disable=protected-access
            home, ["--with-colons", "--list-keys", fingerprint]
        )
    except Exception:  # pylint: disable=broad-except
        return f"<fingerprint {fingerprint}>"
    text = result.stdout.decode("utf-8", errors="replace")
    # uid:<trust>:::<exp>:<sig>:<info>:<hash>:<class>:<uid_str>:...
    match = re.search(
        r"^uid:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:([^:]*):",
        text,
        re.MULTILINE,
    )
    if match:
        uid = match.group(1).strip()
        if uid:
            return uid[:255]
    return f"<fingerprint {fingerprint}>"
